-module(matrix_crypto_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% HKDF — RFC 5869 Test Case 1
%%%
%%% Source: https://www.rfc-editor.org/rfc/rfc5869 Appendix A.1
%%% Hash   = SHA-256
%%% IKM    = 0x0b0b...0b (22 bytes)
%%% Salt   = 0x000102...0c (13 bytes)
%%% Info   = 0xf0f1...f9 (10 bytes)
%%% L      = 42
%%% OKM    = 3cb25f25...5865 (42 bytes)
%%%===================================================================

hkdf_rfc5869_test() ->
    IKM      = binary:copy(<<16#0b>>, 22),
    Salt     = <<16#00,16#01,16#02,16#03,16#04,16#05,16#06,
                 16#07,16#08,16#09,16#0a,16#0b,16#0c>>,
    Info     = <<16#f0,16#f1,16#f2,16#f3,16#f4,
                 16#f5,16#f6,16#f7,16#f8,16#f9>>,
    Expected = <<16#3c,16#b2,16#5f,16#25,16#fa,16#ac,16#d5,16#7a,
                 16#90,16#43,16#4f,16#64,16#d0,16#36,16#2f,16#2a,
                 16#2d,16#2d,16#0a,16#90,16#cf,16#1a,16#5a,16#4c,
                 16#5d,16#b0,16#2d,16#56,16#ec,16#c4,16#c5,16#bf,
                 16#34,16#00,16#72,16#08,16#d5,16#b8,16#87,16#18,
                 16#58,16#65>>,
    Result = matrix_megolm:hkdf(sha256, IKM, Salt, Info, 42),
    ?assertEqual(Expected, Result).

%%%===================================================================
%%% Megolm session_key — vérification de format et d'encodage
%%%
%%% Spec Megolm:
%%%   Format: VERSION(1) | COUNTER(4 big) | R0-R3(128) | Ed25519_pub(32) | Sig(64)
%%%   Total : 229 bytes
%%%   VERSION = 2
%%%   Signature: Ed25519 sur les 165 premiers bytes (avant sig)
%%%===================================================================

session_key_length_test() ->
    {ok, Session} = matrix_megolm:create_outbound(),
    Key = matrix_megolm:outbound_session_key(Session),
    ?assertEqual(229, byte_size(Key)).

session_key_version_test() ->
    {ok, Session} = matrix_megolm:create_outbound(),
    <<Version:8, _/binary>> = matrix_megolm:outbound_session_key(Session),
    ?assertEqual(2, Version).

session_key_signature_valid_test() ->
    {ok, Session} = matrix_megolm:create_outbound(),
    Key = matrix_megolm:outbound_session_key(Session),
    %% Layout: version(1) + counter(4) + R0-R3(128) + ed25519_pub(32) + sig(64) = 229
    SigOffset  = 229 - 64,
    Unsigned   = binary:part(Key, 0, SigOffset),
    Sig        = binary:part(Key, SigOffset, 64),
    EdPub      = binary:part(Key, SigOffset - 32, 32),
    ?assert(crypto:verify(eddsa, none, Unsigned, Sig, [EdPub, ed25519])).

session_key_b64u_no_padding_test() ->
    {ok, Session} = matrix_megolm:create_outbound(),
    Key    = matrix_megolm:outbound_session_key(Session),
    B64    = matrix_e2e:b64u(Key),
    %% Unpadded base64 ne doit jamais contenir '='
    ?assertEqual(nomatch, binary:match(B64, <<"=">>)).

%%%===================================================================
%%% Règle globale : b64u ne produit jamais de padding
%%%===================================================================

b64u_no_padding_test() ->
    %% Cas qui génèrent du padding en base64 standard :
    %% len mod 3 == 1 → padding "=="
    %% len mod 3 == 2 → padding "="
    lists:foreach(fun(Len) ->
        Bin = crypto:strong_rand_bytes(Len),
        B64 = matrix_e2e:b64u(Bin),
        ?assertEqual(nomatch, binary:match(B64, <<"=">>))
    end, lists:seq(1, 33)).
