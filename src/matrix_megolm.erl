%%%===================================================================
%%% matrix_megolm.erl — Megolm inbound + outbound sessions
%%%===================================================================
-module(matrix_megolm).

-export([
    %% Inbound
    init_inbound/1, decrypt/2, session_id/1, pickle/1, unpickle/1,
    hmac/2, pkcs7unpad/1, decode_varint/1,
    %% Outbound (NEW)
    create_outbound/0,
    outbound_session_key/1,
    outbound_session_id/1,
    encrypt_outbound/2,
    pickle_outbound/1,
    unpickle_outbound/1
]).

%% Inbound session
-record(mgm, {
    counter = 0 :: non_neg_integer(),
    r0 :: binary(), r1 :: binary(), r2 :: binary(), r3 :: binary(),
    ed25519_pub = undefined :: binary() | undefined
}).

%% Outbound session (NEW)
-record(mgm_out, {
    counter = 0  :: non_neg_integer(),
    r0           :: binary(),
    r1           :: binary(),
    r2           :: binary(),
    r3           :: binary(),
    ed25519_pub  :: binary(),
    ed25519_priv :: binary()
}).

-define(HKDF_INFO,   <<"MEGOLM_KEYS">>).
-define(MSG_VERSION, 3).
-define(KEY_VERSION, 2).

%%%===================================================================
%%% OUTBOUND API (NEW)
%%%===================================================================

-spec create_outbound() -> {ok, #mgm_out{}}.
create_outbound() ->
    {EdPub, EdPriv} = crypto:generate_key(eddsa, ed25519),
    R0 = crypto:strong_rand_bytes(32),
    R1 = crypto:strong_rand_bytes(32),
    R2 = crypto:strong_rand_bytes(32),
    R3 = crypto:strong_rand_bytes(32),
    {ok, #mgm_out{r0=R0, r1=R1, r2=R2, r3=R3,
                   ed25519_pub=EdPub, ed25519_priv=EdPriv}}.

%% Returns the session key binary to share with room members.
-spec outbound_session_key(#mgm_out{}) -> binary().
outbound_session_key(#mgm_out{counter=C, r0=R0, r1=R1, r2=R2, r3=R3, ed25519_pub=EP}) ->
    <<?KEY_VERSION:8, C:32/big, R0/binary, R1/binary, R2/binary, R3/binary, EP/binary>>.

%% Returns the session ID (unpadded base64 of the Ed25519 pub).
-spec outbound_session_id(#mgm_out{}) -> binary().
outbound_session_id(#mgm_out{ed25519_pub=EP}) ->
    b64u(EP).

%% Encrypts a plaintext binary, returns {ok, CiphertextBin, UpdatedSession}.
-spec encrypt_outbound(#mgm_out{}, binary()) -> {ok, binary(), #mgm_out{}}.
encrypt_outbound(Session = #mgm_out{counter=Idx, ed25519_priv=EdPriv}, Plaintext) ->
    {AesKey, MacKey, AesIv} = derive_keys_out(Session),
    Padded  = pkcs7pad(Plaintext, 16),
    Ct      = crypto:crypto_one_time(aes_256_cbc, AesKey, AesIv, Padded, true),
    IdxV    = encode_varint(Idx),
    CtLenV  = encode_varint(byte_size(Ct)),
    MsgBody = <<(?MSG_VERSION):8, 16#08:8, IdxV/binary,
                16#12:8, CtLenV/binary, Ct/binary>>,
    Mac  = binary:part(hmac(MacKey, MsgBody), 0, 8),
    Msg0 = <<MsgBody/binary, Mac/binary>>,
    Sig  = crypto:sign(eddsa, none, Msg0, [EdPriv, ed25519]),
    Msg  = <<Msg0/binary, Sig/binary>>,
    {ok, Msg, advance_outbound(Session)}.

-spec pickle_outbound(#mgm_out{}) -> binary().
pickle_outbound(S) -> term_to_binary(S).

-spec unpickle_outbound(binary()) -> {ok, #mgm_out{}} | {error, bad_pickle}.
unpickle_outbound(Bin) ->
    try {ok, binary_to_term(Bin, [safe])}
    catch _:_ -> {error, bad_pickle}
    end.

%%%===================================================================
%%% INBOUND API (unchanged)
%%%===================================================================

init_inbound(SessionKeyBin) ->
    parse_session_key(SessionKeyBin).

decrypt(Session, CiphertextBin) ->
    try
        <<?MSG_VERSION:8, 16#08:8, R1/binary>> = CiphertextBin,
        {MsgIndex, <<16#12:8, R2/binary>>} = decode_varint(R1),
        {CtLen, R3} = decode_varint(R2),
        Ct        = binary:part(R3, 0, CtLen),
        MacOffset = byte_size(CiphertextBin) - byte_size(R3) + CtLen,
        Mac       = binary:part(CiphertextBin, MacOffset, 8),
        MsgForMac = binary:part(CiphertextBin, 0, MacOffset),
        Session2  = advance(Session, MsgIndex),
        {AesKey, MacKey, AesIv} = derive_keys(Session2),
        ExpectedMac = binary:part(hmac(MacKey, MsgForMac), 0, 8),
        case ExpectedMac =:= Mac of
            false ->
                {error, mac_mismatch};
            true ->
                PlainPadded = crypto:crypto_one_time(aes_256_cbc, AesKey, AesIv, Ct, false),
                Plaintext   = pkcs7unpad(PlainPadded),
                Session3    = advance(Session2, MsgIndex + 1),
                {ok, {Plaintext, MsgIndex, Session3}}
        end
    catch C:R:_Stack ->
        {error, {decrypt_failed, C, R}}
    end.

session_id(#mgm{ed25519_pub = undefined}) -> <<>>;
session_id(#mgm{ed25519_pub = Pub})       -> Pub.

pickle(S)     -> term_to_binary(S).
unpickle(Bin) ->
    try {ok, binary_to_term(Bin, [safe])}
    catch _:_ -> {error, bad_pickle}
    end.

%%%===================================================================
%%% Inbound ratchet
%%%===================================================================

advance(S = #mgm{counter = Ctr}, Target) when Ctr >= Target -> S;
advance(S = #mgm{counter = Ctr, r0 = R0, r1 = R1, r2 = R2, r3 = R3}, Target) ->
    Next = Ctr + 1,
    {NR0, NR1, NR2, NR3} =
        if (Next band 16#FFFFFF) =:= 0 ->
               {hmac(R0, <<0>>), hmac(R0, <<1>>), hmac(R0, <<2>>), hmac(R0, <<3>>)};
           (Next band 16#FFFF) =:= 0 ->
               {R0, hmac(R1, <<1>>), hmac(R1, <<2>>), hmac(R1, <<3>>)};
           (Next band 16#FF) =:= 0 ->
               {R0, R1, hmac(R2, <<2>>), hmac(R2, <<3>>)};
           true ->
               {R0, R1, R2, hmac(R3, <<3>>)}
        end,
    advance(S#mgm{counter = Next, r0 = NR0, r1 = NR1, r2 = NR2, r3 = NR3}, Target).

derive_keys(#mgm{r0 = R0, r1 = R1, r2 = R2, r3 = R3}) ->
    IKM  = <<R0/binary, R1/binary, R2/binary, R3/binary>>,
    Keys = hkdf(sha256, IKM, <<>>, ?HKDF_INFO, 80),
    <<AesKey:32/binary, MacKey:32/binary, AesIv:16/binary>> = Keys,
    {AesKey, MacKey, AesIv}.

%%%===================================================================
%%% Outbound ratchet (NEW)
%%%===================================================================

advance_outbound(S = #mgm_out{counter=Ctr, r0=R0, r1=R1, r2=R2, r3=R3}) ->
    Next = Ctr + 1,
    {NR0, NR1, NR2, NR3} =
        if (Next band 16#FFFFFF) =:= 0 ->
               {hmac(R0, <<0>>), hmac(R0, <<1>>), hmac(R0, <<2>>), hmac(R0, <<3>>)};
           (Next band 16#FFFF) =:= 0 ->
               {R0, hmac(R1, <<1>>), hmac(R1, <<2>>), hmac(R1, <<3>>)};
           (Next band 16#FF) =:= 0 ->
               {R0, R1, hmac(R2, <<2>>), hmac(R2, <<3>>)};
           true ->
               {R0, R1, R2, hmac(R3, <<3>>)}
        end,
    S#mgm_out{counter=Next, r0=NR0, r1=NR1, r2=NR2, r3=NR3}.

derive_keys_out(#mgm_out{r0=R0, r1=R1, r2=R2, r3=R3}) ->
    IKM  = <<R0/binary, R1/binary, R2/binary, R3/binary>>,
    Keys = hkdf(sha256, IKM, <<>>, ?HKDF_INFO, 80),
    <<AesKey:32/binary, MacKey:32/binary, AesIv:16/binary>> = Keys,
    {AesKey, MacKey, AesIv}.

%%%===================================================================
%%% Shared HKDF / crypto
%%%===================================================================

hkdf(Hash, IKM, Salt, Info, Len) ->
    PRK = crypto:mac(hmac, Hash, Salt, IKM),
    hkdf_expand(Hash, PRK, Info, 1, <<>>, <<>>, Len).

hkdf_expand(_Hash, _PRK, _Info, _I, _Prev, OKM, Len)
        when byte_size(OKM) >= Len ->
    binary:part(OKM, 0, Len);
hkdf_expand(Hash, PRK, Info, I, Prev, OKM, Len) ->
    T = crypto:mac(hmac, Hash, PRK, <<Prev/binary, Info/binary, I:8>>),
    hkdf_expand(Hash, PRK, Info, I + 1, T, <<OKM/binary, T/binary>>, Len).

hmac(Key, Data) -> crypto:mac(hmac, sha256, Key, Data).

pkcs7unpad(Bin) ->
    Len    = byte_size(Bin),
    PadLen = binary:last(Bin),
    case PadLen >= 1 andalso PadLen =< Len of
        true  -> binary:part(Bin, 0, Len - PadLen);
        false -> error({bad_padding, PadLen, Len})
    end.

pkcs7pad(Bin, BlockSize) ->
    Pad = BlockSize - (byte_size(Bin) rem BlockSize),
    <<Bin/binary, (binary:copy(<<Pad>>, Pad))/binary>>.

decode_varint(Bin) -> decode_varint(Bin, 0, 0).
decode_varint(<<1:1, B:7, Rest/binary>>, Shift, Acc) ->
    decode_varint(Rest, Shift + 7, Acc bor (B bsl Shift));
decode_varint(<<0:1, B:7, Rest/binary>>, Shift, Acc) ->
    {Acc bor (B bsl Shift), Rest};
decode_varint(_, _, _) ->
    {0, <<>>}.

encode_varint(N) when N < 128 -> <<N>>;
encode_varint(N) ->
    <<1:1, (N band 127):7, (encode_varint(N bsr 7))/binary>>.

b64u(Bin) ->
    B = base64:encode(Bin),
    << <<C>> || <<C>> <= B, C =/= $= >>.

%%%===================================================================
%%% Inbound session key parser
%%%===================================================================

parse_session_key(Bin) ->
    try
        case Bin of
            <<?KEY_VERSION:8, Counter:32/big-unsigned,
              R0:32/binary, R1:32/binary, R2:32/binary, R3:32/binary,
              Ed25519Pub:32/binary, _/binary>> ->
                {ok, #mgm{counter = Counter,
                          r0 = R0, r1 = R1, r2 = R2, r3 = R3,
                          ed25519_pub = Ed25519Pub}};
            <<?KEY_VERSION:8, Counter:32/big-unsigned,
              R0:32/binary, R1:32/binary, R2:32/binary, R3:32/binary, _/binary>> ->
                {ok, #mgm{counter = Counter,
                          r0 = R0, r1 = R1, r2 = R2, r3 = R3}}
        end
    catch _:_ ->
        {error, bad_session_key}
    end.
