%%%===================================================================
%%% matrix_olm_session.erl — Olm account and session management
%%%
%%% Implements the Olm double-ratchet protocol (https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md):
%%%   - Account management: identity keys, one-time keys (OTKs)
%%%   - Outbound: create pre-key messages (type 0) to initiate a session
%%%   - Inbound:  create sessions from incoming pre-key messages (type 0)
%%%   - Decrypt ratchet messages (type 1) on established sessions
%%%
%%% Note: key fields inside protobuf are unpadded standard base64,
%%% matching libolm wire format.
%%%===================================================================
-module(matrix_olm_session).

-export([
    %% Self-test
    test_olm_roundtrip/0,
    %% Account management
    create_account/0,
    account_identity_keys/1,
    account_ed25519_keypair/1,
    account_one_time_keys/1,
    account_generate_otks/2,
    account_mark_otks_published/1,
    account_remove_otk/2,
    %% Session — outbound (pre-key) and inbound
    create_olm_prekey_message/4,
    create_inbound/3,
    decrypt/3,
    %% Serialization
    pickle_account/1,
    unpickle_account/1,
    pickle_session/1,
    unpickle_session/1
]).

-type curve25519_keypair() :: {binary(), binary()}.

-record(account, {
    identity_keypair  :: curve25519_keypair(),
    ed25519_keypair   :: {binary(), binary()},
    one_time_keys     :: #{binary() => curve25519_keypair()},
    published_otk_ids :: [binary()]
}).

-record(olm_session, {
    root_key          :: binary(),
    recv_chain        :: binary(),
    dh_keypair        :: curve25519_keypair(),
    their_ratchet_pub :: binary(),
    skipped = #{}     :: #{}
}).

-define(OLM_ROOT_INFO,    <<"OLM_ROOT">>).
-define(OLM_RATCHET_INFO, <<"OLM_RATCHET">>).
-define(OLM_KEYS_INFO,    <<"OLM_KEYS">>).
-define(MSG_KEY_SEED,     <<1>>).
-define(CHAIN_KEY_SEED,   <<2>>).
-define(MSG_VERSION,      3).

%%%===================================================================
%%% Account Management
%%%===================================================================

-spec create_account() -> {ok, #account{}}.
create_account() ->
    {ok, #account{
        identity_keypair  = generate_curve25519_keypair(),
        ed25519_keypair   = generate_ed25519_keypair(),
        one_time_keys     = #{},
        published_otk_ids = []
    }}.

-spec account_identity_keys(#account{}) -> #{binary() => binary()}.
account_identity_keys(#account{identity_keypair = {Pub, _},
                                ed25519_keypair  = {EdPub, _}}) ->
    #{<<"curve25519">> => b64u(Pub),
      <<"ed25519">>    => b64u(EdPub)}.

-spec account_ed25519_keypair(#account{}) -> {binary(), binary()}.
account_ed25519_keypair(#account{ed25519_keypair = KP}) -> KP.

-spec account_one_time_keys(#account{}) -> #{binary() => binary()}.
account_one_time_keys(#account{one_time_keys = OTKs, published_otk_ids = Published}) ->
    maps:fold(fun(KeyId, {Pub, _}, Acc) ->
        case lists:member(KeyId, Published) of
            true  -> Acc;
            false -> maps:put(<<"curve25519:", KeyId/binary>>, b64u(Pub), Acc)
        end
    end, #{}, OTKs).

-spec account_generate_otks(#account{}, pos_integer()) -> #account{}.
account_generate_otks(Acc = #account{one_time_keys = OTKs}, N) ->
    NewOTKs = lists:foldl(fun(_, Map) ->
        maps:put(generate_key_id(), generate_curve25519_keypair(), Map)
    end, OTKs, lists:seq(1, N)),
    Acc#account{one_time_keys = NewOTKs}.

-spec account_mark_otks_published(#account{}) -> #account{}.
account_mark_otks_published(Acc = #account{one_time_keys = OTKs,
                                            published_otk_ids = Published}) ->
    Acc#account{published_otk_ids = lists:usort(Published ++ maps:keys(OTKs))}.

-spec account_remove_otk(#account{}, binary()) -> #account{}.
account_remove_otk(Acc = #account{one_time_keys = OTKs}, OtkPubB64) ->
    Acc#account{one_time_keys = maps:filter(
        fun(_, {Pub, _}) -> b64u(Pub) =/= OtkPubB64 end, OTKs)}.

%%%===================================================================
%%% Outbound: Olm pre-key message (type 0)
%%%
%%% Outer wire format (version 3):
%%%   0x03 | protobuf (no MAC on outer pre-key messages)
%%%     field 1 (tag 0x0A, bytes) = one_time_key  — recipient OTK raw Curve25519 pub (32 bytes)
%%%     field 2 (tag 0x12, bytes) = base_key      — sender ephemeral pub (32 bytes)
%%%     field 3 (tag 0x1A, bytes) = identity_key  — sender identity pub (32 bytes)
%%%     field 4 (tag 0x22, bytes) = inner ratchet message (raw bytes)
%%%
%%% Inner ratchet message wire format:
%%%   0x03 | protobuf | MAC(8 bytes)
%%%     field 1 (bytes)  = ratchet_key  — raw Curve25519 key (= base_key on first msg)
%%%     field 2 (varint) = index        — 0 for the first message
%%%     field 4 (bytes)  = ciphertext   — AES-256-CBC, PKCS7-padded
%%%
%%% Key fields are raw bytes in protobuf — libolm wire convention.
%%%===================================================================
-spec create_olm_prekey_message(#account{}, binary(), binary(), binary()) ->
        {ok, binary()} | {error, term()}.
%%
%% Produces a libolm-compatible Olm pre-key message (type 0).
%%
%% Wire format (matches libolm / Element):
%%   Outer: VERSION(0x03) | PROTOBUF | MAC(8 bytes)
%%     protobuf fields (raw bytes, NOT base64):
%%       field 1 = one_time_key  — recipient's OTK raw Curve25519 pub (32 bytes)
%%       field 2 = base_key      — sender's ephemeral Curve25519 pub  (32 bytes)
%%       field 3 = identity_key  — sender's identity Curve25519 pub   (32 bytes)
%%       field 4 = message       — inner ratchet message bytes
%%   Inner (Olm ratchet message):
%%     VERSION(0x03) | PROTOBUF | MAC(8 bytes)
%%       field 1 = ratchet_key  — sender's ratchet pub (raw bytes, 32 bytes)
%%       field 2 = index        — varint, 0 for first message
%%       field 3 = ciphertext   — AES-256-CBC encrypted bytes
%%
create_olm_prekey_message(Account, TheirCurveB64, TheirOtkB64, Plaintext) ->
    try
        TheirIdKey = b64_decode(TheirCurveB64),
        %% OTK from /keys/claim may be bare base64 OR a signed map {<<"key">>: base64}
        TheirOtk   = extract_otk_bytes(TheirOtkB64),
        #account{identity_keypair = {IdPub, IdPriv}} = Account,

        %% Fresh ephemeral base key
        {BasePub, BasePriv} = generate_curve25519_keypair(),

        %% X3DH outbound (Alice), matching vodozemac / libolm:
        %%   S1 = ECDH(I_A, OT_B) = ecdh(identity_priv, their_otk_pub)
        %%   S2 = ECDH(E_A, I_B)  = ecdh(base_priv,     their_identity_pub)
        %%   S3 = ECDH(E_A, OT_B) = ecdh(base_priv,     their_otk_pub)
        %%   IKM = S1 || S2 || S3  (96 bytes, no prefix)
        S1 = ecdh(IdPriv,   TheirOtk),
        S2 = ecdh(BasePriv, TheirIdKey),
        S3 = ecdh(BasePriv, TheirOtk),

        IKM = <<S1/binary, S2/binary, S3/binary>>,
        <<_RootKey:32/binary, ChainKey:32/binary>> =
            hkdf(sha256, IKM, <<0:256>>, ?OLM_ROOT_INFO, 64),

        MsgKey = hmac256(ChainKey, ?MSG_KEY_SEED),
        {AesKey, MacKey, AesIv} = derive_olm_keys(MsgKey),

        %% The ratchet key for this first message = BasePub (as per Olm spec,
        %% the initial ratchet key is the base/ephemeral key).
        RatchetPub = BasePub,

        %% Encrypt plaintext
        Padded = pkcs7pad(Plaintext, 16),
        Ct     = crypto:crypto_one_time(aes_256_cbc, AesKey, AesIv, Padded, true),

        %% Inner ratchet message (type 1) — libolm lib/message.cpp field IDs:
        %%   field 1 = ratchet_key (bytes) — raw 32-byte Curve25519 key
        %%   field 2 = counter     (varint)
        %%   field 4 = ciphertext  (bytes)  ← NOT 3, libolm CIPHERTEXT_ID = 4
        %% Wire: VERSION(0x03) | PROTOBUF | MAC(8 bytes)
        InnerPb   = encode_pb([{1, RatchetPub}, {2, 0}, {4, Ct}]),
        InnerHead = <<3:8, InnerPb/binary>>,
        InnerMac  = binary:part(hmac256(MacKey, InnerHead), 0, 8),
        InnerMsg  = <<InnerHead/binary, InnerMac/binary>>,

        %% Outer pre-key message (type 0) — libolm lib/message.c tag constants:
        %%   field 1 (tag 0x0A) = one_time_key  — raw 32-byte Curve25519 key
        %%   field 2 (tag 0x12) = base_key      — raw 32-byte Curve25519 key
        %%   field 3 (tag 0x1A) = identity_key  — raw 32-byte Curve25519 key
        %%   field 4 (tag 0x22) = message       — inner ratchet message bytes
        %% Wire: VERSION(0x03) | PROTOBUF  (no trailing MAC on outer pre-key messages)
        OuterPb  = encode_pb([{1, TheirOtk}, {2, BasePub}, {3, IdPub}, {4, InnerMsg}]),
        OuterMsg = <<3:8, OuterPb/binary>>,
        {ok, OuterMsg}
    catch C:R:St ->
        {error, {prekey_failed, C, R, St}}
    end.

%% Extract raw OTK bytes from either a bare base64 string
%% or a signed key map #{<<"key">> => Base64}.
-spec extract_otk_bytes(binary() | map()) -> binary().
extract_otk_bytes(B) when is_binary(B) ->
    b64_decode(B);
extract_otk_bytes(M) when is_map(M) ->
    b64_decode(maps:get(<<"key">>, M)).

%%%===================================================================
%%% Session Creation (Inbound)
%%%===================================================================

-spec create_inbound(#account{}, binary(), binary()) ->
        {ok, binary(), #olm_session{}, #account{}} | {error, term()}.
create_inbound(Account, SenderIdentityKeyB64, PreKeyMsgBin) ->
    try
        #{base_key     := BaseKeyB64,
          one_time_key := OtkKeyB64,
          message      := InnerMsg} = parse_prekey_message(PreKeyMsgBin),

        SenderIdentityKey = maybe_decode(SenderIdentityKeyB64),
        BaseKey           = maybe_decode(BaseKeyB64),
        OtkPub            = maybe_decode(OtkKeyB64),

        #account{identity_keypair = {_IdPub, IdPriv},
                 one_time_keys    = OTKs} = Account,

        {_, OtkPrivKey} = find_otk_by_pub(OTKs, OtkPub),

        %% Inbound X3DH (Bob's perspective), mirroring outbound:
        %%   S1 = ECDH(OT_B, I_A)  = ecdh(OtkPrivKey, SenderIdentityKey)
        %%   S2 = ECDH(I_B,  E_A)  = ecdh(IdPriv,     BaseKey)
        %%   S3 = ECDH(OT_B, E_A)  = ecdh(OtkPrivKey, BaseKey)
        %%   IKM = S1 || S2 || S3  (96 bytes, no prefix)
        S1 = ecdh(OtkPrivKey, SenderIdentityKey),
        S2 = ecdh(IdPriv,     BaseKey),
        S3 = ecdh(OtkPrivKey, BaseKey),

        IKM = <<S1/binary, S2/binary, S3/binary>>,
        <<RootKey:32/binary, ChainKey:32/binary>> =
            hkdf(sha256, IKM, <<0:256>>, ?OLM_ROOT_INFO, 64),

        Session = #olm_session{
            root_key          = RootKey,
            recv_chain        = ChainKey,
            dh_keypair        = generate_curve25519_keypair(),
            their_ratchet_pub = BaseKey
        },

        Account2 = account_remove_otk(Account, OtkKeyB64),

        {ok, Plaintext, Session2} = decrypt_ratchet(Session, InnerMsg, BaseKey),
        {ok, Plaintext, Session2, Account2}
    catch C:R:St ->
        {error, {inbound_session_failed, C, R, St}}
    end.

maybe_decode(B) when byte_size(B) =:= 32 -> B;
maybe_decode(B) -> b64_decode(B).

%%%===================================================================
%%% Message Decryption
%%%===================================================================

-spec decrypt(#olm_session{}, non_neg_integer(), binary()) ->
        {ok, binary(), #olm_session{}} | {error, term()}.
decrypt(Session, 1, CiphertextBin) ->
    try
        #{ratchet_key := RatchetKey,
          message     := Ciphertext} = parse_ratchet_message(CiphertextBin),
        decrypt_ratchet(Session, Ciphertext, maybe_decode(RatchetKey))
    catch C:R ->
        {error, {decrypt_failed, C, R}}
    end;
decrypt(_Session, Type, _) ->
    {error, {unsupported_msg_type, Type}}.

%%%===================================================================
%%% Internal — Double Ratchet
%%%===================================================================

decrypt_ratchet(Session = #olm_session{
                    their_ratchet_pub = CurrentPub,
                    recv_chain        = ChainKey,
                    root_key          = RootKey,
                    dh_keypair        = {_MyPub, MyPriv}
                  }, Ciphertext, TheirRatchetKey) ->
    {ChainKey2, Session2} =
        case TheirRatchetKey =:= CurrentPub of
            true ->
                {ChainKey, Session};
            false ->
                DhSecret = ecdh(MyPriv, TheirRatchetKey),
                <<NewRootKey:32/binary, NewChainKey:32/binary>> =
                    hkdf(sha256, <<RootKey/binary, DhSecret/binary>>,
                         <<0:256>>, ?OLM_RATCHET_INFO, 64),
                S2 = Session#olm_session{
                    root_key          = NewRootKey,
                    recv_chain        = NewChainKey,
                    dh_keypair        = generate_curve25519_keypair(),
                    their_ratchet_pub = TheirRatchetKey
                },
                {NewChainKey, S2}
        end,

    MsgKey       = hmac256(ChainKey2, ?MSG_KEY_SEED),
    NewChainKey2 = hmac256(ChainKey2, ?CHAIN_KEY_SEED),
    {AesKey, MacKey, AesIv} = derive_olm_keys(MsgKey),

    MsgLen   = byte_size(Ciphertext),
    MacStart = MsgLen - 8,
    <<Body:MacStart/binary, Mac:8/binary>> = Ciphertext,
    ExpMac = binary:part(crypto:mac(hmac, sha256, MacKey, Body), 0, 8),
    case ExpMac =:= Mac of
        false -> {error, mac_mismatch};
        true  ->
            <<_BodyVersion:8, InnerPb/binary>> = Body,
            Fields = decode_protobuf(InnerPb),
            RawCt  = maps:get(4, Fields),
            case keylara_aes:decrypt(RawCt, AesKey, AesIv) of
                {ok, Plaintext} ->
                    {ok, Plaintext, Session2#olm_session{recv_chain = NewChainKey2}};
                Err -> Err
            end
    end.

derive_olm_keys(MsgKey) ->
    <<AesKey:32/binary, MacKey:32/binary, AesIv:16/binary>> =
        hkdf(sha256, MsgKey, <<>>, ?OLM_KEYS_INFO, 80),
    {AesKey, MacKey, AesIv}.

%%%===================================================================
%%% Message Parsing
%%%===================================================================

parse_prekey_message(<<_Version:8, Bin/binary>>) ->
    Fields = decode_protobuf(Bin),
    OTK  = maps:get(1, Fields, <<>>),   %% one_time_key  tag 0x0A = field 1
    BK   = maps:get(2, Fields, <<>>),   %% base_key      tag 0x12 = field 2
    IK   = maps:get(3, Fields, <<>>),   %% identity_key  tag 0x1A = field 3
    Msg4 = maps:get(4, Fields, <<>>),   %% message       tag 0x22 = field 4
    #{one_time_key => OTK,
      base_key     => BK,
      identity_key => IK,
      message      => Msg4}.

parse_ratchet_message(Bin) ->
    <<?MSG_VERSION:8, Rest/binary>> = Bin,
    Fields = decode_protobuf(Rest),
    %% ratchet_key is raw bytes (libolm wire) or base64 — maybe_decode handles both
    #{ratchet_key => maps:get(1, Fields),
      index       => varint_to_integer(maps:get(2, Fields, <<0>>)),
      message     => maps:get(4, Fields)}.

varint_to_integer(B) when is_binary(B)  -> element(1, decode_varint(B));
varint_to_integer(N) when is_integer(N) -> N.

decode_protobuf(Bin) -> decode_protobuf(Bin, #{}).

decode_protobuf(<<>>, Acc) -> Acc;
decode_protobuf(Bin,  Acc) ->
    {Tag, Rest} = decode_varint(Bin),
    FieldNum = Tag bsr 3,
    WireType = Tag band 7,
    case WireType of
        0 ->
            {Value, Rest2} = decode_varint(Rest),
            decode_protobuf(Rest2, maps:put(FieldNum, Value, Acc));
        2 ->
            {Len, Rest2} = decode_varint(Rest),
            <<Value:Len/binary, Rest3/binary>> = Rest2,
            decode_protobuf(Rest3, maps:put(FieldNum, Value, Acc));
        _ -> Acc
    end.

decode_varint(Bin) -> decode_varint(Bin, 0, 0).
decode_varint(<<1:1, B:7, Rest/binary>>, Shift, Acc) ->
    decode_varint(Rest, Shift + 7, Acc bor (B bsl Shift));
decode_varint(<<0:1, B:7, Rest/binary>>, Shift, Acc) ->
    {Acc bor (B bsl Shift), Rest}.

%%%===================================================================
%%% Protobuf encoder
%%%===================================================================

encode_pb(Fields) ->
    iolist_to_binary([encode_pb_field(FN, V) || {FN, V} <- Fields]).

encode_pb_field(FN, V) when is_binary(V) ->
    Tag = encode_varint((FN bsl 3) bor 2),
    [Tag, encode_varint(byte_size(V)), V];
encode_pb_field(FN, V) when is_integer(V) ->
    Tag = encode_varint((FN bsl 3) bor 0),
    [Tag, encode_varint(V)].

encode_varint(N) when N < 128 -> <<N>>;
encode_varint(N) ->
    <<1:1, (N band 127):7, (encode_varint(N bsr 7))/binary>>.

%%%===================================================================
%%% Crypto helpers
%%%===================================================================

%% HKDF-SHA256 (RFC 5869). crypto:hkdf/5 is not available on all OTP builds.
hkdf(Hash, IKM, Salt, Info, Len) ->
    PRK = hmac256(Salt, IKM),
    hkdf_expand(Hash, PRK, Info, 1, <<>>, <<>>, Len).

hkdf_expand(_Hash, _PRK, _Info, _I, _Prev, OKM, Len) when byte_size(OKM) >= Len ->
    binary:part(OKM, 0, Len);
hkdf_expand(Hash, PRK, Info, I, Prev, OKM, Len) ->
    T = crypto:mac(hmac, Hash, PRK, <<Prev/binary, Info/binary, I:8>>),
    hkdf_expand(Hash, PRK, Info, I + 1, T, <<OKM/binary, T/binary>>, Len).

ecdh(PrivKey, PubKey) ->
    crypto:compute_key(ecdh, PubKey, PrivKey, x25519).

hmac256(Key, Data) ->
    crypto:mac(hmac, sha256, Key, Data).

pkcs7pad(Bin, BlockSize) ->
    Pad = BlockSize - (byte_size(Bin) rem BlockSize),
    <<Bin/binary, (binary:copy(<<Pad>>, Pad))/binary>>.

generate_curve25519_keypair() ->
    crypto:generate_key(ecdh, x25519).

generate_ed25519_keypair() ->
    crypto:generate_key(eddsa, ed25519).

generate_key_id() ->
    Bytes = try
        case keylara:get_entropy_bytes(4) of
            {ok, B} -> B;
            _       -> crypto:strong_rand_bytes(4)
        end
    catch _:_ ->
        crypto:strong_rand_bytes(4)
    end,
    binary:encode_hex(Bytes).

find_otk_by_pub(OTKs, OtkPub) ->
    case maps:fold(fun(_, KP = {Pub, _}, Acc) ->
        case Pub =:= OtkPub of
            true  -> KP;
            false -> Acc
        end
    end, not_found, OTKs) of
        not_found -> throw({error, one_time_key_not_found});
        KP        -> KP
    end.

%% Unpadded standard base64 (libolm wire format for key fields in protobuf).
b64u(Bin) ->
    B = base64:encode(Bin),
    << <<C>> || <<C>> <= B, C =/= $= >>.

b64_decode(B64) ->
    Padded = case byte_size(B64) rem 4 of
        0 -> B64;
        N -> <<B64/binary, (binary:copy(<<"=">>, 4 - N))/binary>>
    end,
    base64:decode(Padded).

%%%===================================================================
%%% Self-test: Olm round-trip
%%%===================================================================

test_olm_roundtrip() ->
    {ok, Alice} = create_account(),
    {ok, Bob0}  = create_account(),
    Bob1 = account_generate_otks(Bob0, 1),
    Bob2 = account_mark_otks_published(Bob1),

    BobIdKeys = account_identity_keys(Bob2),
    BobCurve  = maps:get(<<"curve25519">>, BobIdKeys),

    [{OtkPub, _}] = maps:values(Bob2#account.one_time_keys),
    OtkPubB64 = b64u(OtkPub),

    Plaintext = <<"olm round-trip test">>,
    {ok, PrekeyMsg} = create_olm_prekey_message(Alice, BobCurve, OtkPubB64, Plaintext),
    io:format("[olm-rt] prekey_bytes=~p~n", [byte_size(PrekeyMsg)]),

    AliceIdKeys = account_identity_keys(Alice),
    AliceCurve  = maps:get(<<"curve25519">>, AliceIdKeys),

    case create_inbound(Bob2, AliceCurve, PrekeyMsg) of
        {ok, Decrypted, _Session, _Bob3} ->
            Match = Decrypted =:= Plaintext,
            io:format("[olm-rt] decrypted_ok=true match=~p~n", [Match]),
            Match;
        {error, E} ->
            io:format("[olm-rt] FAILED: ~p~n", [E]),
            false
    end.

%%%===================================================================
%%% Pickle / Unpickle
%%%===================================================================

pickle_account(Acc)   -> term_to_binary(Acc).
unpickle_account(Bin) ->
    try {ok, binary_to_term(Bin, [safe])}
    catch _:_ -> {error, bad_pickle}
    end.

pickle_session(S)    -> term_to_binary(S).
unpickle_session(Bin) ->
    try {ok, binary_to_term(Bin, [safe])}
    catch _:_ -> {error, bad_pickle}
    end.
