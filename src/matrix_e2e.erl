%%%===================================================================
%%% matrix_e2e.erl — E2E encryption state manager (gen_server)
%%%
%%% Responsibilities:
%%%   - Manage Olm account, OTK upload, cross-signing keys
%%%   - Decrypt incoming Megolm room events
%%%   - Encrypt outgoing room events with per-room outbound Megolm sessions
%%%   - Share Megolm session keys to room members via Olm pre-key messages
%%%   - Handle m.room_key_request: re-share keys to devices that missed them
%%%   - SAS device verification (m.sas.v1)
%%%   - Key backup import (Curve25519-AES-CBC backup format)
%%%===================================================================
-module(matrix_e2e).
-behaviour(gen_server).

-export([start_link/2, decrypt_room_event/1, handle_to_device/1, device_keys/0,
         request_room_key/3, upload_device_self_signature/7, b64u/1,
         reupload_device_sig/0, verify_with/2, fetch_backup_keys/1,
         encrypt_room_event/2, reset_outbound_sessions/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(STATE_FILE, "matrix_e2e_state.bin").
-define(OTK_TARGET, 50).

-record(verif, {
    txn_id          :: binary(),
    their_user_id   :: binary(),
    their_device_id :: binary(),
    our_ephem_pub   = undefined,
    our_ephem_priv  = undefined,
    their_ephem_pub = undefined,
    start_content   = undefined,
    shared_secret   = undefined
}).

-record(state, {
    account,
    device_id       :: binary(),
    user_id         :: binary() | undefined,
    token           :: binary(),
    homeserver      :: string(),
    megolm_sessions  = #{} :: #{},
    olm_sessions     = #{} :: #{},
    cross_signing_master   = undefined,
    cross_signing_self     = undefined,
    cross_signing_user     = undefined,
    cross_signing_uploaded = false :: boolean(),
    verifications          = #{} :: #{},
    %% Outbound Megolm sessions, one per room.
    %% #{RoomId => {SessionId::binary(), Pickle::binary()}}
    megolm_outbound        = #{} :: #{}
}).

%%%===================================================================
%%% Public API
%%%===================================================================

-spec start_link(binary(), string()) -> {ok, pid()} | {error, term()}.
start_link(Token, HomeserverUrl) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Token, HomeserverUrl], []).

-spec decrypt_room_event(map()) -> {ok, map()} | {error, term()}.
decrypt_room_event(Event) ->
    gen_server:call(?MODULE, {decrypt_room_event, Event}, 15000).

-spec handle_to_device([map()]) -> ok.
handle_to_device(Events) ->
    gen_server:cast(?MODULE, {to_device_events, Events}).

-spec device_keys() -> {ok, map()} | {error, term()}.
device_keys() ->
    gen_server:call(?MODULE, device_keys).

-spec request_room_key(binary(), binary(), binary()) -> ok.
request_room_key(RoomId, SessionId, SenderKey) ->
    gen_server:cast(?MODULE, {request_room_key, RoomId, SessionId, SenderKey}).

-spec reupload_device_sig() -> ok.
reupload_device_sig() ->
    gen_server:cast(?MODULE, reupload_device_sig).

-spec verify_with(binary(), binary()) -> ok.
verify_with(UserId, DeviceId) ->
    gen_server:cast(?MODULE, {verify_with, UserId, DeviceId}).

%% Encrypts a room event using the outbound Megolm session for RoomId.
%% EventContent must include <<"type">>, <<"content">>, and <<"room_id">>.
%% Returns {ok, EncryptedContent} — an m.room.encrypted payload ready to PUT.
-spec encrypt_room_event(binary(), map()) -> {ok, map()} | {error, term()}.
encrypt_room_event(RoomId, EventContent) ->
    gen_server:call(?MODULE, {encrypt_room_event, RoomId, EventContent}, 30000).

%% Drop all cached outbound Megolm sessions. Next send will create fresh
%% sessions and re-share keys via Olm to all room members.
-spec reset_outbound_sessions() -> ok.
reset_outbound_sessions() ->
    gen_server:call(?MODULE, reset_outbound_sessions).

%%%===================================================================
%%% gen_server
%%%===================================================================

init([Token, HomeserverUrl]) ->
    case keylara:start() of
        ok               -> ok;
        {error, _Reason} -> ok
    end,
    Hostname = extract_hostname(HomeserverUrl),
    State    = load_state(Token, Hostname),
    {UserId, Did} = case matrix_http:get(Hostname,
                                          "/_matrix/client/v3/account/whoami", Token) of
        {ok, Body} ->
            Data = json:decode(Body),
            {maps:get(<<"user_id">>,   Data, undefined),
             maps:get(<<"device_id">>, Data, State#state.device_id)};
        _ ->
            {undefined, State#state.device_id}
    end,
    io:format("E2E: authenticated as ~s device ~s~n", [UserId, Did]),
    case os:getenv("MATRIX_BACKUP_KEY") of
        false -> ok;
        RKey  ->
            io:format("E2E: auto-fetching backup keys from env~n"),
            self() ! {fetch_backup_keys, list_to_binary(RKey)}
    end,
    self() ! upload_keys,
    {ok, State#state{user_id = UserId, device_id = Did}}.

handle_call({decrypt_room_event, Event}, _From, State) ->
    {Result, NewState} = do_decrypt_room_event(Event, State),
    {reply, Result, NewState};
handle_call({fetch_backup_keys, RecoveryKey}, _From, State) ->
    {Result, NewState} = do_fetch_backup_keys(RecoveryKey, State),
    save_state(NewState),
    {reply, Result, NewState};
handle_call(device_keys, _From, State) ->
    Keys = matrix_olm_session:account_identity_keys(State#state.account),
    {reply, {ok, Keys#{<<"device_id">> => State#state.device_id}}, State};
handle_call({encrypt_room_event, RoomId, EventContent}, _From, State) ->
    {Result, NewState} = do_encrypt_room_event(RoomId, EventContent, State),
    {reply, Result, NewState};
handle_call(reset_outbound_sessions, _From, State) ->
    NewState = State#state{megolm_outbound = #{}},
    save_state(NewState),
    io:format("E2E: outbound sessions reset~n"),
    {reply, ok, NewState};
handle_call(_R, _F, S) ->
    {reply, {error, unknown_request}, S}.

handle_cast({to_device_events, Events}, State) ->
    NewState = lists:foldl(fun process_to_device/2, State, Events),
    save_state(NewState),
    {noreply, NewState};
handle_cast({verify_with, UserId, DeviceId}, State) ->
    TxnId = gen_request_id(),
    Msg = #{<<"from_device">>    => State#state.device_id,
            <<"methods">>        => [<<"m.sas.v1">>],
            <<"timestamp">>      => erlang:system_time(millisecond),
            <<"transaction_id">> => TxnId},
    send_to_device(State, <<"m.key.verification.request">>, UserId, DeviceId, Msg),
    io:format("E2E: SAS request sent to ~s/~s txn=~s~n", [UserId, DeviceId, TxnId]),
    {noreply, State};
handle_cast(reupload_device_sig, State = #state{
        homeserver           = HS, token = Token,
        device_id            = Did, user_id = UserId, account = Acc,
        cross_signing_self   = {SelfPub, SelfPriv}}) ->
    SelfKeyId = <<"ed25519:", (b64u(SelfPub))/binary>>,
    upload_device_self_signature(HS, Token, Did, UserId, Acc, SelfPriv, SelfKeyId),
    {noreply, State};
handle_cast({request_room_key, RoomId, SessionId, SenderKey}, State) ->
    do_request_room_key(RoomId, SessionId, SenderKey, State),
    {noreply, State};
handle_cast(_M, S) ->
    {noreply, S}.

handle_info(upload_keys, State) ->
    State2 = maybe_upload_keys(State),
    {noreply, State2};
handle_info({fetch_backup_keys, RecoveryKey}, State) ->
    case do_fetch_backup_keys(RecoveryKey, State) of
        {ok, NewState}  -> save_state(NewState), {noreply, NewState};
        {{error, E}, _} ->
            io:format("E2E: auto backup fetch failed: ~p~n", [E]),
            {noreply, State}
    end;
handle_info(_I, S) ->
    {noreply, S}.

terminate(_R, State) ->
    save_state(State),
    ok.

code_change(_OldVsn, S, _E) ->
    {ok, S}.

%%%===================================================================
%%% Outbound Megolm encryption
%%%===================================================================

do_encrypt_room_event(RoomId, EventContent, State) ->
    {Session, SessionId, State2} = ensure_outbound_session(RoomId, State),
    Plaintext = iolist_to_binary(json:encode(EventContent)),
    case matrix_megolm:encrypt_outbound(Session, Plaintext) of
        {ok, Ciphertext, Session2} ->
            Pickle   = matrix_megolm:pickle_outbound(Session2),
            Outbound = maps:put(RoomId, {SessionId, Pickle},
                                State2#state.megolm_outbound),
            State3   = State2#state{megolm_outbound = Outbound},
            IdKeys   = matrix_olm_session:account_identity_keys(State#state.account),
            SenderKey = maps:get(<<"curve25519">>, IdKeys),
            EncContent = #{
                <<"algorithm">>  => <<"m.megolm.v1.aes-sha2">>,
                <<"ciphertext">> => b64u(Ciphertext),
                <<"device_id">>  => State#state.device_id,
                <<"sender_key">> => SenderKey,
                <<"session_id">> => SessionId
            },
            {{ok, EncContent}, State3};
        {error, Reason} ->
            {{error, Reason}, State}
    end.

%% Returns {Session, SessionId, State}.
%% Creates a new outbound session (and shares the key) if none exists.
ensure_outbound_session(RoomId, State) ->
    case maps:get(RoomId, State#state.megolm_outbound, undefined) of
        undefined ->
            {ok, Session} = matrix_megolm:create_outbound(),
            SessionId     = matrix_megolm:outbound_session_id(Session),
            io:format("[e2e-out] new Megolm session ~s for ~s~n", [SessionId, RoomId]),
            %% Share the key with room members asynchronously
            spawn(fun() ->
                try share_megolm_key(RoomId, Session, State)
                catch C:R:St ->
                    io:format("[e2e-out] share_megolm_key CRASH ~p:~p~n~p~n", [C, R, St])
                end
            end),
            Pickle   = matrix_megolm:pickle_outbound(Session),
            Outbound = maps:put(RoomId, {SessionId, Pickle},
                                State#state.megolm_outbound),
            {Session, SessionId, State#state{megolm_outbound = Outbound}};
        {SessionId, Pickle} ->
            {ok, Session} = matrix_megolm:unpickle_outbound(Pickle),
            {Session, SessionId, State}
    end.

%%%===================================================================
%%% Outbound Megolm key sharing — broadcast to all room members
%%%===================================================================

share_megolm_key(RoomId, OutSession, State) ->
    #state{token     = Token,
           homeserver = HS,
           user_id    = UserId,
           device_id  = Did,
           account    = Acc} = State,
    SessionKey = matrix_megolm:outbound_session_key(OutSession),
    SessionId  = matrix_megolm:outbound_session_id(OutSession),
    IdKeys     = matrix_olm_session:account_identity_keys(Acc),
    OurCurve   = maps:get(<<"curve25519">>, IdKeys),
    OurEd      = maps:get(<<"ed25519">>,    IdKeys),

    Members = get_room_joined_members(RoomId, Token, HS),
    OtherMembers = [M || M <- Members, M =/= UserId],

    case OtherMembers of
        [] ->
            io:format("[e2e-out] no other members in ~s, skipping key share~n", [RoomId]);
        _ ->
            io:format("[e2e-out] sharing key with ~p member(s) in ~s~n",
                      [length(OtherMembers), RoomId]),
            DeviceMap = query_device_keys(OtherMembers, Token, HS),
            ClaimReq  = build_claim_request(DeviceMap),
            OtkMap    = claim_one_time_keys(ClaimReq, Token, HS),

            RoomKeyContent = #{
                <<"algorithm">>   => <<"m.megolm.v1.aes-sha2">>,
                <<"room_id">>     => RoomId,
                <<"session_id">>  => SessionId,
                %% libolm validates session_key length == b64_output_length(229)=308 (padded)
                <<"session_key">> => b64u(SessionKey)
            },

            Messages = maps:fold(fun(TargetUserId, UserDevices, MsgAcc) ->
                maps:fold(fun(DevId, {TheirCurve, TheirEd}, MsgAcc2) ->
                    case DevId =:= Did andalso TargetUserId =:= UserId of
                        true -> MsgAcc2;  %% skip ourselves
                        false ->
                            case get_device_otk(OtkMap, TargetUserId, DevId) of
                                not_found ->
                                    io:format("[e2e-out] no OTK for ~s/~s — skip~n",
                                              [TargetUserId, DevId]),
                                    MsgAcc2;
                                {ok, OtkB64} ->
                                    Inner = #{
                                        <<"type">>    => <<"m.room_key">>,
                                        <<"content">> => RoomKeyContent,
                                        <<"sender">>  => UserId,
                                        <<"recipient">> => TargetUserId,
                                        <<"keys">>    => #{<<"ed25519">> => OurEd},
                                        <<"recipient_keys">> => #{<<"ed25519">> => TheirEd}
                                    },
                                    Plaintext = iolist_to_binary(json:encode(Inner)),
                                    case matrix_olm_session:create_olm_prekey_message(
                                            Acc, TheirCurve, OtkB64, Plaintext) of
                                        {ok, PrekeyMsg} ->
                                            EncEvent = #{
                                                <<"algorithm">> =>
                                                    <<"m.olm.v1.curve25519-aes-sha2">>,
                                                <<"sender_key">> => OurCurve,
                                                <<"ciphertext">> => #{
                                                    TheirCurve => #{
                                                        <<"type">> => 0,
                                                        <<"body">> => b64u(PrekeyMsg)
                                                    }
                                                }
                                            },
                                            UserMsgs = maps:get(TargetUserId, MsgAcc2, #{}),
                                            maps:put(TargetUserId,
                                                     maps:put(DevId, EncEvent, UserMsgs),
                                                     MsgAcc2);
                                        {error, E} ->
                                            io:format("[e2e-out] Olm encrypt failed ~s/~s: ~p~n",
                                                      [TargetUserId, DevId, E]),
                                            MsgAcc2
                                    end
                            end
                    end
                end, MsgAcc, UserDevices)
            end, #{}, DeviceMap),

            case map_size(Messages) > 0 of
                false ->
                    io:format("[e2e-out] no messages to send for key share~n");
                true  ->
                    TxnId = integer_to_list(erlang:system_time(millisecond)),
                    Path  = "/_matrix/client/v3/sendToDevice/m.room.encrypted/" ++ TxnId,
                    io:format("[e2e-out] sending room key to ~p user(s): ~p~n",
                              [map_size(Messages), maps:keys(Messages)]),
                    case matrix_http:put(HS, Path, Token, #{<<"messages">> => Messages}) of
                        {ok, Resp} ->
                            io:format("[e2e-out] room key shared OK resp=~s~n", [Resp]);
                        Err ->
                            io:format("[e2e-out] room key share FAILED: ~p~n", [Err])
                    end
            end
    end.

%%%===================================================================
%%% Outbound Megolm key sharing — targeted (respond to key requests)
%%%===================================================================

%% Handles an incoming m.room_key_request to-device event.
%% If we hold the requested outbound session, we re-share it to the
%% requesting device only.
handle_key_request(Sender, Content, State) ->
    case maps:get(<<"action">>, Content, <<>>) of
        <<"request">> ->
            Body     = maps:get(<<"body">>,                 Content, #{}),
            ReqDevId = maps:get(<<"requesting_device_id">>, Content, <<>>),
            RoomId   = maps:get(<<"room_id">>,    Body, <<>>),
            SessId   = maps:get(<<"session_id">>, Body, <<>>),
            case maps:get(RoomId, State#state.megolm_outbound, undefined) of
                {SessId, Pickle} ->
                    io:format("E2E: key request from ~s/~s for session ~s — sharing~n",
                              [Sender, ReqDevId, SessId]),
                    {ok, Session} = matrix_megolm:unpickle_outbound(Pickle),
                    spawn(fun() ->
                        try share_megolm_key_to_device(RoomId, Session, Sender, ReqDevId, State)
                        catch C:R:St ->
                            io:format("E2E: share_megolm_key_to_device crash ~p:~p~n~p~n",
                                      [C, R, St])
                        end
                    end),
                    State;
                _ ->
                    io:format("E2E: key request for unknown session ~s from ~s — ignoring~n",
                              [SessId, Sender]),
                    State
            end;
        _ ->
            State
    end.

%% Shares the outbound Megolm session key to a single target device via Olm.
share_megolm_key_to_device(RoomId, Session, TargetUserId, TargetDevId, State) ->
    #state{token=Token, homeserver=HS, user_id=UserId, account=Acc} = State,
    SessionKey = matrix_megolm:outbound_session_key(Session),
    SessionId  = matrix_megolm:outbound_session_id(Session),
    IdKeys     = matrix_olm_session:account_identity_keys(Acc),
    OurCurve   = maps:get(<<"curve25519">>, IdKeys),
    OurEd      = maps:get(<<"ed25519">>,    IdKeys),
    DeviceMap  = query_device_keys([TargetUserId], Token, HS),
    case maps:get(TargetUserId, DeviceMap, undefined) of
        undefined ->
            io:format("[e2e-out] key-req share: no device keys for ~s~n", [TargetUserId]);
        UserDevs ->
            case maps:get(TargetDevId, UserDevs, undefined) of
                undefined ->
                    io:format("[e2e-out] key-req share: device ~s/~s not found~n",
                              [TargetUserId, TargetDevId]);
                {TheirCurve, TheirEd} ->
                    ClaimReq = #{TargetUserId => #{TargetDevId => <<"signed_curve25519">>}},
                    OtkMap   = claim_one_time_keys(ClaimReq, Token, HS),
                    case get_device_otk(OtkMap, TargetUserId, TargetDevId) of
                        not_found ->
                            io:format("[e2e-out] key-req share: no OTK for ~s/~s~n",
                                      [TargetUserId, TargetDevId]);
                        {ok, OtkB64} ->
                            RoomKeyContent = #{
                                <<"algorithm">>   => <<"m.megolm.v1.aes-sha2">>,
                                <<"room_id">>     => RoomId,
                                <<"session_id">>  => SessionId,
                                <<"session_key">> => b64u(SessionKey)
                            },
                            Inner = #{
                                <<"type">>           => <<"m.room_key">>,
                                <<"content">>        => RoomKeyContent,
                                <<"sender">>         => UserId,
                                <<"recipient">>      => TargetUserId,
                                <<"keys">>           => #{<<"ed25519">> => OurEd},
                                <<"recipient_keys">> => #{<<"ed25519">> => TheirEd}
                            },
                            Plaintext = iolist_to_binary(json:encode(Inner)),
                            case matrix_olm_session:create_olm_prekey_message(
                                     Acc, TheirCurve, OtkB64, Plaintext) of
                                {ok, PrekeyMsg} ->
                                    EncEvent = #{
                                        <<"algorithm">>  => <<"m.olm.v1.curve25519-aes-sha2">>,
                                        <<"sender_key">> => OurCurve,
                                        <<"ciphertext">> => #{
                                            TheirCurve => #{
                                                <<"type">> => 0,
                                                <<"body">> => b64u(PrekeyMsg)
                                            }
                                        }
                                    },
                                    TxnId = integer_to_list(erlang:system_time(millisecond)),
                                    Path  = "/_matrix/client/v3/sendToDevice/m.room.encrypted/"
                                            ++ TxnId,
                                    Msgs = #{TargetUserId => #{TargetDevId => EncEvent}},
                                    case matrix_http:put(HS, Path, Token,
                                                         #{<<"messages">> => Msgs}) of
                                        {ok, _} ->
                                            io:format("[e2e-out] key-req share sent to ~s/~s~n",
                                                      [TargetUserId, TargetDevId]);
                                        Err ->
                                            io:format("[e2e-out] key-req share failed: ~p~n", [Err])
                                    end;
                                {error, E} ->
                                    io:format("[e2e-out] key-req Olm encrypt failed: ~p~n", [E])
                            end
                    end
            end
    end.

%%%===================================================================
%%% HTTP helpers for key sharing
%%%===================================================================

get_room_joined_members(RoomId, Token, HS) ->
    Path = "/_matrix/client/v3/rooms/" ++
           uri_string:quote(binary_to_list(RoomId)) ++ "/members",
    case matrix_http:get(HS, Path, Token) of
        {ok, Body} ->
            Data  = json:decode(Body),
            Chunk = maps:get(<<"chunk">>, Data, []),
            [maps:get(<<"state_key">>, E, <<>>) || E <- Chunk,
             maps:get(<<"type">>, E, <<>>) =:= <<"m.room.member">>,
             maps:get(<<"membership">>,
                      maps:get(<<"content">>, E, #{}), <<>>) =:= <<"join">>];
        Err ->
            io:format("[e2e-out] get members failed: ~p~n", [Err]),
            []
    end.

%% Returns #{UserId => #{DevId => {CurveKeyB64, EdKeyB64}}}
query_device_keys(UserIds, Token, HS) ->
    DevKeys = maps:from_list([{U, []} || U <- UserIds]),
    case matrix_http:post(HS, "/_matrix/client/v3/keys/query", Token,
                          #{<<"device_keys">> => DevKeys}) of
        {ok, Body} ->
            AllDevKeys = maps:get(<<"device_keys">>, json:decode(Body), #{}),
            maps:fold(fun(UserId, UserDevs, Acc) ->
                DevMap = maps:fold(fun(DevId, DevData, DA) ->
                    Keys     = maps:get(<<"keys">>, DevData, #{}),
                    CurveKey = maps:get(<<"curve25519:", DevId/binary>>, Keys, undefined),
                    EdKey    = maps:get(<<"ed25519:",    DevId/binary>>, Keys, undefined),
                    case {CurveKey, EdKey} of
                        {C, E} when C =/= undefined, E =/= undefined ->
                            maps:put(DevId, {C, E}, DA);
                        _ -> DA
                    end
                end, #{}, UserDevs),
                case map_size(DevMap) > 0 of
                    true  -> maps:put(UserId, DevMap, Acc);
                    false -> Acc
                end
            end, #{}, AllDevKeys);
        Err ->
            io:format("[e2e-out] keys/query failed: ~p~n", [Err]),
            #{}
    end.

build_claim_request(DeviceMap) ->
    maps:fold(fun(UserId, UserDevs, Acc) ->
        DevClaims = maps:fold(fun(DevId, _, DA) ->
            maps:put(DevId, <<"signed_curve25519">>, DA)
        end, #{}, UserDevs),
        maps:put(UserId, DevClaims, Acc)
    end, #{}, DeviceMap).

claim_one_time_keys(ClaimReq, Token, HS) ->
    case matrix_http:post(HS, "/_matrix/client/v3/keys/claim", Token,
                          #{<<"one_time_keys">> => ClaimReq}) of
        {ok, Body} ->
            maps:get(<<"one_time_keys">>, json:decode(Body), #{});
        Err ->
            io:format("[e2e-out] keys/claim failed: ~p~n", [Err]),
            #{}
    end.

get_device_otk(OtkMap, UserId, DevId) ->
    case maps:get(UserId, OtkMap, undefined) of
        undefined -> not_found;
        UserOtks  ->
            case maps:get(DevId, UserOtks, undefined) of
                undefined -> not_found;
                DevOtks   ->
                    %% DevOtks = #{"curve25519:KEYID" => Val}
                    %% Val is either a bare base64 binary (unsigned OTK)
                    %% or a map #{"key" => base64, "signatures" => ...} (signed OTK).
                    %% We pass the raw value to create_olm_prekey_message which
                    %% handles both via extract_otk_bytes/1.
                    case maps:values(DevOtks) of
                        []      -> not_found;
                        [V | _] ->
                            io:format("[e2e-out] claimed OTK for ~s/~s type=~s~n",
                                      [UserId, DevId,
                                       case is_map(V) of true -> <<"signed">>; false -> <<"bare">> end]),
                            {ok, V}
                    end
            end
    end.

%%%===================================================================
%%% State persistence
%%%===================================================================

save_state(State) ->
    file:write_file(?STATE_FILE, term_to_binary(State#state{token = <<>>})).

load_state(Token, Hostname) ->
    case file:read_file(?STATE_FILE) of
        {ok, Bin} ->
            try
                S = migrate_state(binary_to_term(Bin)),
                io:format("E2E: loaded state (device_id=~s)~n", [S#state.device_id]),
                S#state{token = Token, homeserver = Hostname}
            catch Cls:Err ->
                io:format("E2E: corrupt state (~p:~p), starting fresh~n", [Cls, Err]),
                file:rename(?STATE_FILE, ?STATE_FILE ++ ".bak"),
                fresh_state(Token, Hostname)
            end;
        _ ->
            io:format("E2E: no state file, creating fresh account~n"),
            fresh_state(Token, Hostname)
    end.

migrate_state(S) when is_record(S, state) ->
    Fields  = record_info(fields, state),
    Indices = lists:zip(Fields, lists:seq(2, length(Fields) + 1)),
    Default = #state{},
    lists:foldl(fun({_Field, Idx}, Acc) ->
        case element(Idx, S) of
            undefined -> setelement(Idx, Acc, element(Idx, Default));
            _         -> Acc
        end
    end, S, Indices);
migrate_state(_) ->
    throw(unknown_record).

fresh_state(Token, Hostname) ->
    {ok, Acc0} = matrix_olm_session:create_account(),
    Acc1       = matrix_olm_session:account_generate_otks(Acc0, ?OTK_TARGET),
    MasterKey  = crypto:generate_key(eddsa, ed25519),
    SelfKey    = crypto:generate_key(eddsa, ed25519),
    UserKey    = crypto:generate_key(eddsa, ed25519),
    #state{
        account                = Acc1,
        device_id              = generate_device_id(),
        token                  = Token,
        homeserver             = Hostname,
        cross_signing_master   = MasterKey,
        cross_signing_self     = SelfKey,
        cross_signing_user     = UserKey,
        cross_signing_uploaded = false
    }.

%%%===================================================================
%%% Key Upload
%%%===================================================================

maybe_upload_keys(State = #state{token = Token, homeserver = HS,
                                  account = Acc, device_id = Did,
                                  user_id = UserId}) ->
    OtkCount = fetch_otk_count(HS, Token, Did),
    io:format("E2E: server has ~p OTK(s)~n", [OtkCount]),
    Acc2 = case OtkCount < ?OTK_TARGET div 2 of
        true ->
            ToGen = ?OTK_TARGET - OtkCount,
            io:format("E2E: generating ~p new OTKs~n", [ToGen]),
            matrix_olm_session:account_generate_otks(Acc, ToGen);
        false ->
            Acc
    end,
    upload_keys(HS, Token, Did, UserId, Acc2),
    Acc3   = matrix_olm_session:account_mark_otks_published(Acc2),
    State1 = State#state{account = Acc3},
    State2 = maybe_upload_cross_signing(State1),
    save_state(State2),
    State2.

upload_keys(_HS, _Token, _Did, undefined, _Acc) ->
    io:format("E2E: skipping key upload, user_id not yet known~n");
upload_keys(HS, Token, Did, UserId, Acc) ->
    IdKeys = matrix_olm_session:account_identity_keys(Acc),
    OtkMap = matrix_olm_session:account_one_time_keys(Acc),
    Ed     = maps:get(<<"ed25519">>,    IdKeys),
    Curve  = maps:get(<<"curve25519">>, IdKeys),
    DeviceKeys0 = #{
        <<"algorithms">> => [<<"m.olm.v1.curve25519-aes-sha2">>,
                              <<"m.megolm.v1.aes-sha2">>],
        <<"device_id">>  => Did,
        <<"user_id">>    => UserId,
        <<"keys">>       => #{
            <<"curve25519:", Did/binary>> => Curve,
            <<"ed25519:",    Did/binary>> => Ed
        }
    },
    Sig        = sign_json_raw(DeviceKeys0, Acc),
    SigKey     = <<"ed25519:", Did/binary>>,
    DeviceKeys = DeviceKeys0#{
        <<"signatures">> => #{UserId => #{SigKey => Sig}}
    },
    Body = #{
        <<"device_keys">>   => DeviceKeys,
        <<"one_time_keys">> => OtkMap
    },
    case matrix_http:post(HS, "/_matrix/client/v3/keys/upload", Token, Body) of
        {ok, _} -> io:format("E2E: keys uploaded (~p OTK)~n", [map_size(OtkMap)]);
        Err     -> io:format("E2E: key upload error ~p~n", [Err])
    end.

fetch_otk_count(HS, Token, _Did) ->
    case matrix_http:post(HS, "/_matrix/client/v3/keys/upload", Token, #{}) of
        {ok, Body} ->
            Data = json:decode(Body),
            maps:get(<<"curve25519">>,
                     maps:get(<<"one_time_key_counts">>, Data, #{}), 0);
        _ -> 0
    end.

%%%===================================================================
%%% Cross-signing Key Upload
%%%===================================================================

maybe_upload_cross_signing(State = #state{cross_signing_uploaded = true}) ->
    State;
maybe_upload_cross_signing(State = #state{
        token      = Token,
        homeserver = HS,
        user_id    = UserId}) when UserId =/= undefined ->
    ServerHasMasterKey = case matrix_http:post(HS, "/_matrix/client/v3/keys/query",
                                               Token, #{<<"device_keys">> => #{UserId => []}}) of
        {ok, Body} ->
            Data       = json:decode(Body),
            MasterKeys = maps:get(<<"master_keys">>, Data, #{}),
            UserMaster = maps:get(UserId, MasterKeys, #{}),
            Keys       = maps:get(<<"keys">>, UserMaster, #{}),
            map_size(Keys) > 0;
        _ -> false
    end,
    case ServerHasMasterKey of
        true ->
            io:format("E2E: server already has master key, skipping cross-signing upload~n"),
            try_sign_device_with_local_key(State);
        false ->
            do_upload_cross_signing(State)
    end;
maybe_upload_cross_signing(State) ->
    State.

try_sign_device_with_local_key(State = #state{
        token              = Token,
        homeserver         = HS,
        device_id          = Did,
        user_id            = UserId,
        account            = Acc,
        cross_signing_self = {SelfPub, SelfPriv}}) ->
    SelfKeyId = <<"ed25519:", (b64u(SelfPub))/binary>>,
    upload_device_self_signature(HS, Token, Did, UserId, Acc, SelfPriv, SelfKeyId),
    State#state{cross_signing_uploaded = true};
try_sign_device_with_local_key(State) ->
    State#state{cross_signing_uploaded = true}.

do_upload_cross_signing(State = #state{
        token                = Token,
        homeserver           = HS,
        device_id            = Did,
        user_id              = UserId,
        account              = Acc,
        cross_signing_master = {MasterPub, MasterPriv},
        cross_signing_self   = {SelfPub, SelfPriv},
        cross_signing_user   = {UserPub, _UserPriv}}) ->
    MasterPubB64 = b64u(MasterPub),
    SelfPubB64   = b64u(SelfPub),
    UserPubB64   = b64u(UserPub),
    MasterKeyId  = <<"ed25519:", MasterPubB64/binary>>,
    SelfKeyId    = <<"ed25519:", SelfPubB64/binary>>,
    UserKeyId    = <<"ed25519:", UserPubB64/binary>>,

    MasterObj0 = #{<<"user_id">> => UserId, <<"usage">> => [<<"master">>],
                   <<"keys">> => #{MasterKeyId => MasterPubB64}},
    MasterObj  = MasterObj0#{<<"signatures">> => #{UserId => #{
                   <<"ed25519:", Did/binary>> => sign_json_raw(MasterObj0, Acc)}}},

    SelfObj0 = #{<<"user_id">> => UserId, <<"usage">> => [<<"self_signing">>],
                 <<"keys">> => #{SelfKeyId => SelfPubB64}},
    SelfObj  = SelfObj0#{<<"signatures">> => #{UserId => #{
                 MasterKeyId => sign_json_ed25519(SelfObj0, MasterPriv)}}},

    UserObj0 = #{<<"user_id">> => UserId, <<"usage">> => [<<"user_signing">>],
                 <<"keys">> => #{UserKeyId => UserPubB64}},
    UserObj  = UserObj0#{<<"signatures">> => #{UserId => #{
                 MasterKeyId => sign_json_ed25519(UserObj0, MasterPriv)}}},

    Payload = #{<<"master_key">>       => MasterObj,
                <<"self_signing_key">> => SelfObj,
                <<"user_signing_key">> => UserObj},

    io:format("E2E: uploading cross-signing keys~n"),
    CrossSigningPath = "/_matrix/client/v3/keys/device_signing/upload",
    Result = case matrix_http:post(HS, CrossSigningPath, Token, Payload) of
        {ok, _} = Ok                         -> Ok;
        {error, {status, 401, UiaBody}}      -> uia_retry(HS, CrossSigningPath, Token, Payload, UserId, UiaBody);
        {error, {http_error, 401, UiaBody}}  -> uia_retry(HS, CrossSigningPath, Token, Payload, UserId, UiaBody);
        Other                                -> Other
    end,
    case Result of
        {ok, _} ->
            io:format("E2E: cross-signing keys uploaded OK~n"),
            upload_device_self_signature(HS, Token, Did, UserId, Acc, SelfPriv, SelfKeyId),
            State#state{cross_signing_uploaded = true};
        uia_no_password ->
            io:format("E2E: cross-signing needs UIA — set MATRIX_BOT_PASSWORD env var~n"),
            State;
        Err ->
            io:format("E2E: cross-signing upload failed: ~p~n", [Err]),
            State
    end.

uia_retry(HS, Path, Token, Payload, UserId, UiaBody) ->
    case os:getenv("MATRIX_BOT_PASSWORD") of
        false ->
            uia_no_password;
        Password ->
            UiaData    = json:decode(UiaBody),
            SessionId  = maps:get(<<"session">>, UiaData, <<>>),
            AuthPayload = Payload#{<<"auth">> => #{
                <<"type">>       => <<"m.login.password">>,
                <<"session">>    => SessionId,
                <<"password">>   => list_to_binary(Password),
                <<"identifier">> => #{
                    <<"type">> => <<"m.id.user">>,
                    <<"user">> => UserId
                }
            }},
            io:format("E2E: retrying with UIA (session=~s)~n", [SessionId]),
            matrix_http:post(HS, Path, Token, AuthPayload)
    end.

upload_device_self_signature(HS, Token, Did, UserId, Acc, SelfPriv, SelfKeyId) ->
    IdKeys = matrix_olm_session:account_identity_keys(Acc),
    Ed     = maps:get(<<"ed25519">>,    IdKeys),
    Curve  = maps:get(<<"curve25519">>, IdKeys),
    DevObj0 = #{<<"algorithms">> => [<<"m.olm.v1.curve25519-aes-sha2">>,
                                      <<"m.megolm.v1.aes-sha2">>],
                <<"device_id">>  => Did, <<"user_id">> => UserId,
                <<"keys">>       => #{<<"curve25519:", Did/binary>> => Curve,
                                      <<"ed25519:",    Did/binary>> => Ed}},
    DevObj = DevObj0#{<<"signatures">> => #{UserId => #{
                <<"ed25519:", Did/binary>> => sign_json_raw(DevObj0, Acc),
                SelfKeyId                 => sign_json_ed25519(DevObj0, SelfPriv)}}},
    case matrix_http:post(HS, "/_matrix/client/v3/keys/signatures/upload",
                          Token, #{UserId => #{Did => DevObj}}) of
        {ok, _} -> io:format("E2E: device self-signature uploaded OK~n");
        Err     -> io:format("E2E: device self-signature upload failed: ~p~n", [Err])
    end.

%%%===================================================================
%%% To-device event dispatcher
%%%===================================================================

process_to_device(Event, State) ->
    Type    = maps:get(<<"type">>,    Event, <<>>),
    Content = maps:get(<<"content">>, Event, #{}),
    Sender  = maps:get(<<"sender">>,  Event, <<>>),
    io:format("E2E: to-device type=~s from=~s~n", [Type, Sender]),
    case Type of
        <<"m.room.encrypted">> ->
            case maps:get(<<"algorithm">>, Content, <<>>) of
                <<"m.olm.v1.curve25519-aes-sha2">> ->
                    handle_olm_to_device(Sender, Content, State);
                Algo ->
                    io:format("E2E: unknown to-device algo ~s~n", [Algo]),
                    State
            end;
        <<"m.room_key_request">>          -> handle_key_request(Sender, Content, State);
        <<"m.key.verification.request">> -> handle_verif_request(Sender, Content, State);
        <<"m.key.verification.start">>   -> handle_verif_start(Sender, Content, State);
        <<"m.key.verification.key">>     -> handle_verif_key(Sender, Content, State);
        <<"m.key.verification.mac">>     -> handle_verif_mac(Sender, Content, State);
        <<"m.key.verification.cancel">>  ->
            TxnId  = maps:get(<<"transaction_id">>, Content, <<>>),
            Reason = maps:get(<<"reason">>, Content, <<"unknown">>),
            io:format("E2E: verification cancelled txn=~s reason=~s~n", [TxnId, Reason]),
            State#state{verifications = maps:remove(TxnId, State#state.verifications)};
        _ -> State
    end.

%%%===================================================================
%%% SAS Verification
%%%===================================================================

handle_verif_request(Sender, Content, State) ->
    TxnId      = maps:get(<<"transaction_id">>, Content, gen_request_id()),
    FromDevice = maps:get(<<"from_device">>,    Content, <<>>),
    io:format("E2E: SAS request from ~s/~s txn=~s~n", [Sender, FromDevice, TxnId]),
    V = #verif{txn_id=TxnId, their_user_id=Sender, their_device_id=FromDevice},
    ReadyMsg = #{<<"from_device">>    => State#state.device_id,
                 <<"methods">>        => [<<"m.sas.v1">>],
                 <<"transaction_id">> => TxnId},
    send_to_device(State, <<"m.key.verification.ready">>, Sender, FromDevice, ReadyMsg),
    State#state{verifications = maps:put(TxnId, V, State#state.verifications)}.

handle_verif_start(Sender, Content, State) ->
    TxnId      = maps:get(<<"transaction_id">>, Content, <<>>),
    FromDevice = maps:get(<<"from_device">>,    Content, <<>>),
    io:format("E2E: SAS start from ~s/~s txn=~s~n", [Sender, FromDevice, TxnId]),
    {EphPub, EphPriv} = crypto:generate_key(ecdh, x25519),
    BaseVerif = case maps:get(TxnId, State#state.verifications, undefined) of
        undefined -> #verif{txn_id=TxnId, their_user_id=Sender, their_device_id=FromDevice};
        Existing  -> Existing
    end,
    V = BaseVerif#verif{their_device_id=FromDevice, our_ephem_pub=EphPub,
                        our_ephem_priv=EphPriv, start_content=Content},
    Commitment = sas_commitment(EphPub, Content),
    AcceptMsg = #{
        <<"transaction_id">>              => TxnId,
        <<"method">>                      => <<"m.sas.v1">>,
        <<"key_agreement_protocol">>      => <<"curve25519-hkdf-sha256">>,
        <<"hash">>                        => <<"sha256">>,
        <<"message_authentication_code">> => <<"hkdf-hmac-sha256.v2">>,
        <<"short_authentication_string">> => [<<"emoji">>],
        <<"commitment">>                  => Commitment
    },
    send_to_device(State, <<"m.key.verification.accept">>, Sender, FromDevice, AcceptMsg),
    send_to_device(State, <<"m.key.verification.key">>, Sender, FromDevice,
                   #{<<"transaction_id">> => TxnId, <<"key">> => b64u(EphPub)}),
    State#state{verifications = maps:put(TxnId, V, State#state.verifications)}.

handle_verif_key(_Sender, Content, State) ->
    TxnId       = maps:get(<<"transaction_id">>, Content, <<>>),
    TheirKeyB64 = maps:get(<<"key">>,            Content, <<>>),
    io:format("E2E: SAS key received txn=~s~n", [TxnId]),
    case maps:get(TxnId, State#state.verifications, undefined) of
        undefined ->
            io:format("E2E: SAS key for unknown txn ~s~n", [TxnId]),
            State;
        V ->
            TheirKey     = base64:decode(pad_b64(TheirKeyB64)),
            SharedSecret = crypto:compute_key(ecdh, TheirKey, V#verif.our_ephem_priv, x25519),
            V2 = V#verif{their_ephem_pub=TheirKey, shared_secret=SharedSecret},
            log_sas(SharedSecret, V2, State),
            State2 = State#state{verifications = maps:put(TxnId, V2, State#state.verifications)},
            send_verification_mac(TxnId, V2, State2)
    end.

handle_verif_mac(Sender, Content, State) ->
    TxnId = maps:get(<<"transaction_id">>, Content, <<>>),
    io:format("E2E: SAS MAC received from ~s txn=~s~n", [Sender, TxnId]),
    case maps:get(TxnId, State#state.verifications, undefined) of
        undefined ->
            io:format("E2E: SAS mac for unknown txn ~s~n", [TxnId]),
            State;
        V ->
            send_to_device(State, <<"m.key.verification.done">>,
                           V#verif.their_user_id, V#verif.their_device_id,
                           #{<<"transaction_id">> => TxnId}),
            io:format("E2E: SAS verification COMPLETE with ~s/~s~n",
                      [V#verif.their_user_id, V#verif.their_device_id]),
            State#state{verifications = maps:remove(TxnId, State#state.verifications)}
    end.

send_verification_mac(TxnId, V, State) ->
    #state{user_id=OurUid, device_id=OurDid, account=Acc} = State,
    TheirUid     = V#verif.their_user_id,
    TheirDid     = V#verif.their_device_id,
    SharedSecret = V#verif.shared_secret,
    IdKeys       = matrix_olm_session:account_identity_keys(Acc),
    Ed25519      = maps:get(<<"ed25519">>, IdKeys),
    KeyId        = <<"ed25519:", OurDid/binary>>,
    KeyMac    = sas_mac(SharedSecret, OurUid, OurDid, TheirUid, TheirDid, TxnId,
                        KeyId, Ed25519),
    KeyIdsMac = sas_mac(SharedSecret, OurUid, OurDid, TheirUid, TheirDid, TxnId,
                        <<"KEY_IDS">>, KeyId),
    send_to_device(State, <<"m.key.verification.mac">>, TheirUid, TheirDid, #{
        <<"transaction_id">> => TxnId,
        <<"mac">>            => #{KeyId => KeyMac},
        <<"keys">>           => KeyIdsMac
    }),
    State.

log_sas(SharedSecret, V, #state{user_id=OurUid, device_id=OurDid}) ->
    TheirPubB64 = b64u(V#verif.their_ephem_pub),
    OurPubB64   = b64u(V#verif.our_ephem_pub),
    Info = iolist_to_binary([
        <<"MATRIX_KEY_VERIFICATION_SAS|">>,
        V#verif.their_user_id, <<"|">>, V#verif.their_device_id, <<"|">>, TheirPubB64, <<"|">>,
        OurUid,                <<"|">>, OurDid,                  <<"|">>, OurPubB64,   <<"|">>,
        V#verif.txn_id
    ]),
    <<B0:13, B1:13, B2:13, B3:13, _:8>> = hkdf_sha256(SharedSecret, <<>>, Info, 6),
    io:format("E2E: SAS emoji indices (auto-accepting): ~p ~p ~p ~p~n",
              [B0 rem 64, B1 rem 64, B2 rem 64, B3 rem 64]).

%%%===================================================================
%%% Olm / Megolm inbound
%%%===================================================================

handle_olm_to_device(Sender, Content, State) ->
    IdKeys      = matrix_olm_session:account_identity_keys(State#state.account),
    MyCurve     = maps:get(<<"curve25519">>, IdKeys),
    Ciphertexts = maps:get(<<"ciphertext">>, Content, #{}),
    SenderKey   = maps:get(<<"sender_key">>, Content, <<>>),
    case maps:get(MyCurve, Ciphertexts, undefined) of
        undefined ->
            io:format("E2E: to-device message not addressed to us~n"),
            State;
        #{<<"type">> := MsgType, <<"body">> := Body} ->
            CT         = b64d(to_bin(Body)),
            OlmSessKey = {SenderKey, Sender},
            decrypt_olm_message(MsgType, CT, OlmSessKey, SenderKey, State)
    end.

decrypt_olm_message(0, CT, OlmSessKey, SenderKey, State) ->
    case matrix_olm_session:create_inbound(State#state.account, SenderKey, CT) of
        {ok, Plain, Session, Acc2} ->
            Pkl    = matrix_olm_session:pickle_session(Session),
            Pkls   = maps:put(OlmSessKey, Pkl, State#state.olm_sessions),
            State2 = State#state{account = Acc2, olm_sessions = Pkls},
            process_inner_event(json:decode(Plain), SenderKey, State2);
        Err ->
            io:format("E2E: inbound session creation failed ~p~n", [Err]),
            State
    end;
decrypt_olm_message(1, CT, OlmSessKey, SenderKey, State) ->
    case maps:get(OlmSessKey, State#state.olm_sessions, undefined) of
        undefined ->
            io:format("E2E: no Olm session for sender ~p~n", [SenderKey]),
            State;
        Pkl ->
            {ok, Session} = matrix_olm_session:unpickle_session(Pkl),
            case matrix_olm_session:decrypt(Session, 1, CT) of
                {ok, Plain, Session2} ->
                    Pkls = maps:put(OlmSessKey,
                                    matrix_olm_session:pickle_session(Session2),
                                    State#state.olm_sessions),
                    process_inner_event(json:decode(Plain), SenderKey,
                                        State#state{olm_sessions = Pkls});
                Err ->
                    io:format("E2E: Olm decrypt error ~p~n", [Err]),
                    State
            end
    end;
decrypt_olm_message(T, _, _, _, State) ->
    io:format("E2E: unknown Olm message type ~p~n", [T]),
    State.

process_inner_event(Inner, SenderKey, State) ->
    Type    = maps:get(<<"type">>,    Inner, <<>>),
    Content = maps:get(<<"content">>, Inner, #{}),
    case Type of
        <<"m.room_key">>           -> store_megolm_key(Content, SenderKey, State);
        <<"m.forwarded_room_key">> ->
            io:format("E2E: received forwarded room key~n"),
            store_megolm_key(Content, SenderKey, State);
        _ ->
            io:format("E2E: unhandled inner event type: ~s~n", [Type]),
            State
    end.

store_megolm_key(Content, SenderKey, State) ->
    case maps:get(<<"algorithm">>, Content, <<>>) of
        <<"m.megolm.v1.aes-sha2">> ->
            SessionId = maps:get(<<"session_id">>,  Content, <<>>),
            MegolmKey = maps:get(<<"session_key">>, Content, <<>>),
            RoomId    = maps:get(<<"room_id">>,     Content, <<>>),
            io:format("E2E: received room key ~s / ~s~n", [RoomId, SessionId]),
            RawKey = b64d(to_bin(MegolmKey)),
            case matrix_megolm:init_inbound(RawKey) of
                {ok, MgmSession} ->
                    K  = {RoomId, SessionId, SenderKey},
                    Ms = maps:put(K, matrix_megolm:pickle(MgmSession),
                                  State#state.megolm_sessions),
                    State#state{megolm_sessions = Ms};
                Err ->
                    io:format("E2E: Megolm session init error ~p~n", [Err]),
                    State
            end;
        Algo ->
            io:format("E2E: unknown room key algorithm: ~s~n", [Algo]),
            State
    end.

%%%===================================================================
%%% Room event decryption
%%%===================================================================

do_decrypt_room_event(Event, State) ->
    Content    = maps:get(<<"content">>,    Event, #{}),
    RoomId     = maps:get(<<"room_id">>,    Event, <<>>),
    SenderKey  = maps:get(<<"sender_key">>, Content, <<>>),
    SessionId  = maps:get(<<"session_id">>, Content, <<>>),
    Ciphertext = maps:get(<<"ciphertext">>, Content, <<>>),
    Algo       = maps:get(<<"algorithm">>,  Content, <<>>),
    case Algo of
        <<"m.megolm.v1.aes-sha2">> ->
            %% Try exact match first, then fall back to sender_key-agnostic lookup.
            %% The sender_key in the event may differ from the one stored at backup
            %% import time (e.g. forwarded key, base64 variant, different device).
            ExactKey = {RoomId, SessionId, SenderKey},
            {FoundKey, FoundPickle} =
                case maps:get(ExactKey, State#state.megolm_sessions, undefined) of
                    undefined ->
                        find_session_by_room_and_id(
                            RoomId, SessionId, State#state.megolm_sessions);
                    ExactPickle ->
                        {ExactKey, ExactPickle}
                end,
            case FoundPickle of
                undefined ->
                    io:format("E2E: no Megolm session for ~s / ~s (sender_key=~s)~n",
                              [RoomId, SessionId, SenderKey]),
                    case os:getenv("MATRIX_BACKUP_KEY") of
                        false -> ok;
                        RKey  -> erlang:send_after(5000, self(),
                                     {fetch_backup_keys, list_to_binary(RKey)})
                    end,
                    {{error, no_session}, State};
                FoundPickle ->
                    {ok, MgmSession} = matrix_megolm:unpickle(FoundPickle),
                    CT = b64d(Ciphertext),
                    case matrix_megolm:decrypt(MgmSession, CT) of
                        {ok, {Plain, _Idx, MgmSession2}} ->
                            Ms2 = maps:put(FoundKey, matrix_megolm:pickle(MgmSession2),
                                           State#state.megolm_sessions),
                            {{ok, json:decode(Plain)}, State#state{megolm_sessions = Ms2}};
                        Err ->
                            io:format("E2E: Megolm decrypt error ~p~n", [Err]),
                            {Err, State}
                    end
            end;
        _ ->
            {{error, {unknown_algo, Algo}}, State}
    end.

%% Scan megolm_sessions for any key matching {RoomId, SessionId, _AnySenderKey}.
-spec find_session_by_room_and_id(binary(), binary(), map()) ->
        {tuple(), binary()} | {undefined, undefined}.
find_session_by_room_and_id(RoomId, SessionId, Sessions) ->
    maps:fold(fun
        (K = {R, S, _SK}, Pkl, {undefined, undefined})
                when R =:= RoomId, S =:= SessionId ->
            io:format("E2E: session found via fallback lookup (stored_key =/= event_key)~n"),
            {K, Pkl};
        (_, _, Acc) ->
            Acc
    end, {undefined, undefined}, Sessions).

%%%===================================================================
%%% Room key request
%%%===================================================================

do_request_room_key(RoomId, SessionId, SenderKey,
                    #state{token=Token, homeserver=HS, device_id=Did}) ->
    io:format("E2E: requesting room key for ~s / ~s~n", [RoomId, SessionId]),
    Members   = get_room_joined_members(RoomId, Token, HS),
    DeviceMap = query_device_keys(Members, Token, HS),
    ReqBody   = #{<<"action">>               => <<"request">>,
                  <<"body">>                 => #{
                      <<"algorithm">>  => <<"m.megolm.v1.aes-sha2">>,
                      <<"room_id">>    => RoomId,
                      <<"sender_key">> => SenderKey,
                      <<"session_id">> => SessionId},
                  <<"request_id">>           => gen_request_id(),
                  <<"requesting_device_id">> => Did},
    Messages = maps:fold(fun(UserId, UserDevs, Acc) ->
        DevMsgs = maps:fold(fun(DevId, _, DA) ->
            case DevId =:= Did of
                true  -> DA;
                false -> maps:put(DevId, ReqBody, DA)
            end
        end, #{}, UserDevs),
        case map_size(DevMsgs) > 0 of
            true  -> maps:put(UserId, DevMsgs, Acc);
            false -> Acc
        end
    end, #{}, DeviceMap),
    case map_size(Messages) > 0 of
        false -> io:format("E2E: no devices found to request key from~n");
        true  ->
            TxnId    = integer_to_list(erlang:system_time(millisecond)),
            SendPath = "/_matrix/client/v3/sendToDevice/m.room_key_request/" ++ TxnId,
            case matrix_http:put(HS, SendPath, Token, #{<<"messages">> => Messages}) of
                {ok, _} ->
                    io:format("E2E: room key request sent to ~p user(s)~n",
                              [map_size(Messages)]);
                Err ->
                    io:format("E2E: room key request failed: ~p~n", [Err])
            end
    end.

%%%===================================================================
%%% SAS crypto
%%%===================================================================

sas_commitment(OurEphPub, StartContent) ->
    PubB64 = b64u(OurEphPub),
    Hash   = crypto:hash(sha256, <<PubB64/binary, (canonical_json(StartContent))/binary>>),
    b64u(Hash).

sas_mac(Secret, SenderUid, SenderDid, RecvUid, RecvDid, TxnId, KeyId, Value) ->
    Info = iolist_to_binary([<<"MATRIX_KEY_VERIFICATION_MAC|">>,
                              SenderUid, <<"|">>, SenderDid, <<"|">>,
                              RecvUid,   <<"|">>, RecvDid,   <<"|">>,
                              TxnId,     <<"|">>, KeyId]),
    MacKey = hkdf_sha256(Secret, <<>>, Info, 32),
    b64u(crypto:mac(hmac, sha256, MacKey, Value)).

hkdf_sha256(IKM, Salt0, Info, Length) ->
    Salt = case byte_size(Salt0) of
        0 -> binary:copy(<<0>>, 32);
        _ -> Salt0
    end,
    PRK = crypto:mac(hmac, sha256, Salt, IKM),
    hkdf_expand(PRK, Info, 1, <<>>, <<>>, Length).

hkdf_expand(_PRK, _Info, _I, _Prev, OKM, Length)
    when byte_size(OKM) >= Length ->
    binary:part(OKM, 0, Length);
hkdf_expand(PRK, Info, I, Prev, OKM, Length) ->
    T = crypto:mac(hmac, sha256, PRK, <<Prev/binary, Info/binary, I:8>>),
    hkdf_expand(PRK, Info, I+1, T, <<OKM/binary, T/binary>>, Length).

%%%===================================================================
%%% Generic to-device sender
%%%===================================================================

send_to_device(#state{token=Token, homeserver=HS}, Type, ToUser, ToDevice, Content) ->
    TxnId   = integer_to_list(erlang:system_time(millisecond)),
    Path    = "/_matrix/client/v3/sendToDevice/" ++ binary_to_list(Type) ++ "/" ++ TxnId,
    Payload = #{<<"messages">> => #{ToUser => #{ToDevice => Content}}},
    case matrix_http:put(HS, Path, Token, Payload) of
        {ok, _} -> ok;
        Err     -> io:format("E2E: send_to_device ~s failed: ~p~n", [Type, Err])
    end.

%%%===================================================================
%%% Utilities
%%%===================================================================

extract_hostname("https://" ++ R) -> hd(string:split(R, "/"));
extract_hostname("http://"  ++ R) -> hd(string:split(R, "/"));
extract_hostname(O)               -> O.

to_bin(B) when is_binary(B) -> B;
to_bin(L) when is_list(L)   -> list_to_binary(L).

b64d(B) ->
    base64:decode(pad_b64(B)).

generate_device_id() ->
    {ok, Bytes} = keylara:get_entropy_bytes(10),
    Chars = <<"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789">>,
    << <<(binary:at(Chars, B rem 36))>> || <<B>> <= Bytes >>.

gen_request_id() ->
    list_to_binary("req_" ++ integer_to_list(erlang:system_time(microsecond))).

sign_json_raw(Map, Account) ->
    {_EdPub, EdPriv} = matrix_olm_session:account_ed25519_keypair(Account),
    b64u(crypto:sign(eddsa, none, canonical_json(Map), [EdPriv, ed25519])).

sign_json_ed25519(Map, PrivKey) ->
    b64u(crypto:sign(eddsa, none, canonical_json(Map), [PrivKey, ed25519])).

b64u(Bin) ->
    B = base64:encode(Bin),
    << <<C>> || <<C>> <= B, C =/= $= >>.

pkcs7_unpad(Bin) ->
    PadLen = binary:last(Bin),
    binary:part(Bin, 0, byte_size(Bin) - PadLen).

canonical_json(Map) when is_map(Map) ->
    Pairs = lists:sort(maps:to_list(Map)),
    Inner = lists:join(",", [
        [<<"\"">>, canonical_key(K), <<"\":">>, canonical_json(V)]
        || {K, V} <- Pairs
    ]),
    iolist_to_binary(["{", Inner, "}"]);
canonical_json(List) when is_list(List) ->
    Inner = lists:join(",", [canonical_json(V) || V <- List]),
    iolist_to_binary(["[", Inner, "]"]);
canonical_json(B) when is_binary(B)  -> iolist_to_binary(["\"", B, "\""]);
canonical_json(N) when is_integer(N) -> integer_to_binary(N);
canonical_json(true)                 -> <<"true">>;
canonical_json(false)                -> <<"false">>;
canonical_json(null)                 -> <<"null">>;
canonical_json(undefined)            -> <<"null">>.

canonical_key(K) when is_binary(K) -> K;
canonical_key(K) when is_atom(K)   -> atom_to_binary(K).

%%%===================================================================
%%% Key Backup
%%%===================================================================

-spec fetch_backup_keys(binary() | string()) -> ok | {error, term()}.
fetch_backup_keys(RecoveryKeyStr) ->
    gen_server:call(?MODULE, {fetch_backup_keys, RecoveryKeyStr}, 60000).

do_fetch_backup_keys(RecoveryKeyStr, State = #state{token=Token, homeserver=HS,
                                                     user_id=UserId}) ->
    case decode_recovery_key(RecoveryKeyStr) of
        {error, E} ->
            io:format("E2E: bad recovery key: ~p~n", [E]),
            {{error, bad_recovery_key}, State};
        {ok, RecoveryPrivBytes} ->
            AccDataPath = "/_matrix/client/v3/user/" ++
                          uri_string:quote(binary_to_list(UserId)) ++
                          "/account_data/m.secret_storage.default_key",
            case matrix_http:get(HS, AccDataPath, Token) of
                {error, E2} ->
                    io:format("E2E: could not get default key id: ~p~n", [E2]),
                    {{error, E2}, State};
                {ok, DKBody} ->
                    KeyId = maps:get(<<"key">>, json:decode(DKBody), <<>>),
                    io:format("E2E: secret storage key_id=~s~n", [KeyId]),
                    SecretPath = "/_matrix/client/v3/user/" ++
                                 uri_string:quote(binary_to_list(UserId)) ++
                                 "/account_data/m.megolm_backup.v1",
                    case matrix_http:get(HS, SecretPath, Token) of
                        {error, E3} ->
                            io:format("E2E: could not get backup secret: ~p~n", [E3]),
                            {{error, E3}, State};
                        {ok, SecBody} ->
                            SecData   = json:decode(SecBody),
                            Encrypted = maps:get(<<"encrypted">>, SecData, #{}),
                            KeyEntry  = maps:get(KeyId, Encrypted, #{}),
                            case decrypt_secret_storage(KeyEntry, KeyId, RecoveryPrivBytes) of
                                {error, E4} ->
                                    io:format("E2E: secret decryption failed: ~p~n", [E4]),
                                    {{error, E4}, State};
                                {ok, BackupKeyB64} ->
                                    BackupPrivKey = base64:decode(pad_b64(BackupKeyB64)),
                                    io:format("E2E: backup key decrypted OK (~p bytes)~n",
                                              [byte_size(BackupPrivKey)]),
                                    fetch_and_import_rooms(BackupPrivKey, Token, HS, State)
                            end
                    end
            end
    end.

decrypt_secret_storage(Entry, _KeyId, RecoveryPrivBytes) ->
    try
        IVB64  = maps:get(<<"iv">>,         Entry),
        CtB64  = maps:get(<<"ciphertext">>, Entry),
        MacB64 = maps:get(<<"mac">>,        Entry),
        IV  = base64:decode(pad_b64(IVB64)),
        Ct  = base64:decode(pad_b64(CtB64)),
        Mac = base64:decode(pad_b64(MacB64)),
        Keys   = hkdf_sha256(RecoveryPrivBytes, binary:copy(<<0>>, 32), <<"m.megolm_backup.v1">>, 64),
        AesKey = binary:part(Keys, 0,  32),
        MacKey = binary:part(Keys, 32, 32),
        ExpMac = crypto:mac(hmac, sha256, MacKey, Ct),
        case Mac =:= ExpMac of
            false ->
                io:format("E2E: secret storage MAC mismatch~n"),
                {error, mac_mismatch};
            true ->
                Plain = crypto:crypto_one_time(aes_256_ctr, AesKey, IV, Ct, false),
                {ok, Plain}
        end
    catch Cls:Err ->
        {error, {Cls, Err}}
    end.

fetch_and_import_rooms(BackupPrivKey, Token, HS, State) ->
    case matrix_http:get(HS, "/_matrix/client/v3/room_keys/version", Token) of
        {error, E} ->
            io:format("E2E: backup version fetch failed: ~p~n", [E]),
            {{error, E}, State};
        {ok, VerBody} ->
            VerData  = json:decode(VerBody),
            Version  = maps:get(<<"version">>, VerData, <<"1">>),
            AuthData = maps:get(<<"auth_data">>, VerData, #{}),
            BackupPubB64 = maps:get(<<"public_key">>, AuthData, <<>>),
            io:format("E2E: backup version=~s pubkey=~s~n", [Version, BackupPubB64]),
            KeysPath = "/_matrix/client/v3/room_keys/keys?version=" ++
                       binary_to_list(Version),
            case matrix_http:get(HS, KeysPath, Token) of
                {error, E2} ->
                    io:format("E2E: backup download failed: ~p~n", [E2]),
                    {{error, E2}, State};
                {ok, KeysBody} ->
                    KeysData = json:decode(KeysBody),
                    Rooms    = maps:get(<<"rooms">>, KeysData, #{}),
                    io:format("E2E: decrypting backup for ~p room(s)~n", [map_size(Rooms)]),
                    NewState = import_backup_rooms(Rooms, BackupPrivKey, State),
                    io:format("E2E: backup import complete, ~p sessions total~n",
                              [map_size(NewState#state.megolm_sessions)]),
                    {ok, NewState}
            end
    end.

import_backup_rooms(Rooms, PrivKey, State) ->
    maps:fold(fun(RoomId, RoomData, Acc) ->
        Sessions = maps:get(<<"sessions">>, RoomData, #{}),
        maps:fold(fun(SessionId, SessionData, Acc2) ->
            SessionDataInner = maps:get(<<"session_data">>, SessionData, #{}),
            case decrypt_backup_session(SessionDataInner, PrivKey) of
                {ok, Plain}  -> store_backup_session(RoomId, SessionId, Plain, Acc2);
                {error, E}   ->
                    io:format("E2E: failed to decrypt ~s/~s: ~p~n", [RoomId, SessionId, E]),
                    Acc2
            end
        end, Acc, Sessions)
    end, State, Rooms).

decrypt_backup_session(SessionData, PrivKey) ->
    try
        EphB64  = maps:get(<<"ephemeral">>,  SessionData),
        CtB64   = maps:get(<<"ciphertext">>, SessionData),
        _MacB64 = maps:get(<<"mac">>,        SessionData),
        EphPub = base64:decode(pad_b64(EphB64)),
        Ct     = base64:decode(pad_b64(CtB64)),
        Shared = crypto:compute_key(ecdh, EphPub, PrivKey, x25519),
        Keys   = hkdf_sha256(Shared, binary:copy(<<0>>, 32), <<>>, 80),
        AesKey = binary:part(Keys, 0,  32),
        IV     = binary:part(Keys, 64, 16),
        Plain    = crypto:crypto_one_time(aes_256_cbc, AesKey, IV, Ct, false),
        Unpadded = pkcs7_unpad(Plain),
        {ok, json:decode(Unpadded)}
    catch Cls:Err ->
        {error, {Cls, Err}}
    end.

store_backup_session(RoomId, SessionId, Plain, State) ->
    SenderKey  = maps:get(<<"sender_key">>,  Plain, <<>>),
    SessionKey = maps:get(<<"session_key">>, Plain, <<>>),
    KeyBin = b64d(to_bin(SessionKey)),
    KeyV2  = case KeyBin of
        <<1, Rest/binary>> -> <<2, Rest/binary, 0:512>>;
        Other              -> Other
    end,
    case matrix_megolm:init_inbound(KeyV2) of
        {ok, MgmSession} ->
            K  = {RoomId, SessionId, SenderKey},
            Ms = maps:put(K, matrix_megolm:pickle(MgmSession),
                          State#state.megolm_sessions),
            State#state{megolm_sessions = Ms};
        Err ->
            io:format("E2E: backup session init failed ~s/~s: ~p~n",
                      [RoomId, SessionId, Err]),
            State
    end.

%%%===================================================================
%%% Recovery key decoding
%%%===================================================================

decode_recovery_key(Key) when is_list(Key) ->
    decode_recovery_key(list_to_binary(Key));
decode_recovery_key(Key) when is_binary(Key) ->
    Stripped = binary:replace(Key, [<<" ">>, <<"-">>, <<"\n">>], <<>>, [global]),
    case base58_decode(Stripped) of
        {error, E} -> {error, E};
        Bytes when byte_size(Bytes) =:= 35 ->
            <<16#8B, 16#01, PrivKey:32/binary, Parity>> = Bytes,
            Expected = lists:foldl(fun(B, Acc) -> Acc bxor B end, 0,
                                   binary_to_list(binary:part(Bytes, 0, 34))),
            case Expected band 16#FF of
                Parity -> {ok, PrivKey};
                _      -> {error, bad_parity}
            end;
        Bytes ->
            {error, {bad_length, byte_size(Bytes)}}
    end.

base58_decode(B58) ->
    Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    try
        Num = lists:foldl(fun(C, Acc) ->
            case string:chr(Alphabet, C) of
                0   -> throw({bad_char, C});
                Idx -> Acc * 58 + (Idx - 1)
            end
        end, 0, binary_to_list(B58)),
        num_to_bytes(Num)
    catch throw:E -> {error, E}
    end.

num_to_bytes(N) ->
    Bytes = num_to_bytes_acc(N, <<>>),
    Len   = byte_size(Bytes),
    case Len < 35 of
        true  -> <<(binary:copy(<<0>>, 35 - Len))/binary, Bytes/binary>>;
        false -> Bytes
    end.

num_to_bytes_acc(0, <<>>) -> <<0>>;
num_to_bytes_acc(0, Acc)  -> Acc;
num_to_bytes_acc(N, Acc)  ->
    num_to_bytes_acc(N bsr 8, <<(N band 16#FF), Acc/binary>>).

pad_b64(B) ->
    case byte_size(B) rem 4 of
        0 -> B;
        R -> <<B/binary, (binary:copy(<<"=">>, 4 - R))/binary>>
    end.
