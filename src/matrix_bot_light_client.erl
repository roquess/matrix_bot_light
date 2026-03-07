%%%===================================================================
%%% Matrix Bot Light Client
%%%   handle_message(Content, RoomId, Author, Token)
%%%   handle_slash_command(CommandName, Options, RoomId, EventId, User, Token)
%%%   on_ready(Token)
%%%
%%% Changes:
%%%   - encrypted_rooms: tracks rooms using m.megolm.v1.aes-sha2
%%%   - do_send_message: routes through matrix_e2e when room is encrypted
%%%   - dispatch_message: spawn handlers to avoid calling_self deadlock
%%%===================================================================
-module(matrix_bot_light_client).
-behaviour(gen_server).

-export([start_link/1, start_link/2, start_link/3]).
-export([send_message/3, send_message_with_files/4, edit_message/4]).
-export([get_stored_app_id/0]).
-export([register_global_commands/2, register_global_command/3, register_global_command/4]).
-export([register_guild_command/4, register_guild_command/5]).
-export([respond_to_interaction/3, respond_to_interaction/4]).
-export([respond_to_interaction_with_files/4, respond_to_interaction_with_files/5]).
-export([edit_interaction_response/3, edit_interaction_response/4]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {
    token           :: binary(),
    homeserver      :: string(),
    next_batch      = undefined :: binary() | undefined,
    bot_user_id     = undefined :: binary() | undefined,
    command_handler = undefined :: term(),
    txn_id          = 0         :: non_neg_integer(),
    registered_cmds = []        :: [binary()],
    %% rooms known to use E2E encryption
    encrypted_rooms = sets:new() :: sets:set()
}).

-define(DEFAULT_HOMESERVER, "https://matrix.roques.me").
-define(CONNECTION_TIMEOUT, 30000).
-define(SYNC_TIMEOUT_MS, 20000).
-define(SYNC_TIMEOUT_S, "20000").

%%%===================================================================
%%% Public API
%%%===================================================================

-spec start_link(binary() | string()) -> {ok, pid()} | {error, term()}.
start_link(Token) ->
    start_link(Token, []).

-spec start_link(binary() | string(), list()) -> {ok, pid()} | {error, term()}.
start_link(Token, Options) ->
    Homeserver = get_env_or_default("MATRIX_HOMESERVER", ?DEFAULT_HOMESERVER),
    start_link(Token, Homeserver, Options).

-spec start_link(binary() | string(), string(), list()) -> {ok, pid()} | {error, term()}.
start_link(Token, Homeserver, Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Token, Homeserver, Options], []).

-spec get_stored_app_id() -> {ok, binary()} | {error, not_available}.
get_stored_app_id() ->
    gen_server:call(?MODULE, get_app_id).

-spec send_message(binary(), binary(), binary()) -> {ok, binary()} | {error, term()}.
send_message(RoomId, Content, _Token) ->
    gen_server:call(?MODULE, {send_message, RoomId, Content}, ?CONNECTION_TIMEOUT).

-spec send_message_with_files(binary(), binary(), binary(), [{binary(), binary()}]) ->
        {ok, binary()} | {error, term()}.
send_message_with_files(RoomId, Content, _Token, Files) ->
    gen_server:call(?MODULE, {send_message_with_files, RoomId, Content, Files},
                   ?CONNECTION_TIMEOUT).

-spec edit_message(binary(), binary(), binary(), binary()) ->
        {ok, integer(), binary()} | {error, term()}.
edit_message(RoomId, EventId, NewContent, _Token) ->
    gen_server:call(?MODULE, {edit_message, RoomId, EventId, NewContent},
                   ?CONNECTION_TIMEOUT).

-spec register_global_commands(list(), binary()) -> {ok, list()} | {error, term()}.
register_global_commands(Commands, _Token) ->
    Names = [maps:get(<<"name">>, C) || C <- Commands],
    gen_server:cast(?MODULE, {register_commands, Names}),
    {ok, Commands}.

-spec register_global_command(binary(), binary(), binary()) -> {ok, binary()} | {error, term()}.
register_global_command(CommandName, _Description, _Token) ->
    gen_server:cast(?MODULE, {register_commands, [CommandName]}),
    {ok, CommandName}.

-spec register_global_command(binary(), binary(), list(), binary()) -> {ok, binary()} | {error, term()}.
register_global_command(CommandName, _Description, _Options, _Token) ->
    gen_server:cast(?MODULE, {register_commands, [CommandName]}),
    {ok, CommandName}.

-spec register_guild_command(binary(), binary(), binary(), binary()) -> {ok, binary()} | {error, term()}.
register_guild_command(_GuildId, CommandName, Description, Token) ->
    register_global_command(CommandName, Description, Token).

-spec register_guild_command(binary(), binary(), binary(), list(), binary()) -> {ok, binary()} | {error, term()}.
register_guild_command(_GuildId, CommandName, Description, Options, Token) ->
    register_global_command(CommandName, Description, Options, Token).

-spec respond_to_interaction(binary(), binary(), binary()) -> ok | {error, term()}.
respond_to_interaction(RoomId, _EventId, Content) ->
    case send_message(RoomId, Content, <<>>) of
        {ok, _} -> ok;
        Err     -> Err
    end.

-spec respond_to_interaction(binary(), binary(), binary(), map()) -> ok | {error, term()}.
respond_to_interaction(RoomId, EventId, Content, Options) ->
    case maps:get(reply_to, Options, undefined) of
        undefined    -> respond_to_interaction(RoomId, EventId, Content);
        ReplyEventId ->
            gen_server:call(?MODULE, {send_reply, RoomId, Content, ReplyEventId},
                           ?CONNECTION_TIMEOUT)
    end.

-spec respond_to_interaction_with_files(binary(), binary(), binary(),
                                        [{binary(), binary()}]) -> ok | {error, term()}.
respond_to_interaction_with_files(RoomId, _EventId, Content, Files) ->
    case send_message_with_files(RoomId, Content, <<>>, Files) of
        {ok, _} -> ok;
        Err     -> Err
    end.

-spec respond_to_interaction_with_files(binary(), binary(), binary(),
                                        [{binary(), binary()}], map()) -> ok | {error, term()}.
respond_to_interaction_with_files(RoomId, EventId, Content, Files, _Options) ->
    respond_to_interaction_with_files(RoomId, EventId, Content, Files).

-spec edit_interaction_response(binary(), binary(), binary()) -> ok | {error, term()}.
edit_interaction_response(RoomId, EventId, Content) ->
    edit_interaction_response(RoomId, EventId, Content, #{}).

-spec edit_interaction_response(binary(), binary(), binary(), map()) -> ok | {error, term()}.
edit_interaction_response(RoomId, EventId, Content, _Options) ->
    case edit_message(RoomId, EventId, Content, <<>>) of
        {ok, _, _} -> ok;
        Err        -> Err
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Token, Homeserver, Options]) ->
    process_flag(trap_exit, true),
    HSUrl    = string:trim(Homeserver, trailing, "/"),
    Hostname = extract_hostname(HSUrl),
    CommandHandler = proplists:get_value(command_handler, Options, undefined),
    SavedBatch = load_next_batch(Hostname),
    self() ! start_sync,
    {ok, #state{
        token           = to_binary(Token),
        homeserver      = Hostname,
        next_batch      = SavedBatch,
        command_handler = CommandHandler
    }}.

handle_call(get_app_id, _From, State) ->
    case State#state.bot_user_id of
        undefined -> {reply, {error, not_available}, State};
        UserId    -> {reply, {ok, UserId}, State}
    end;

handle_call({send_message, RoomId, Content}, _From, State) ->
    {Result, NewState} = do_send_message(RoomId, Content, State),
    {reply, Result, NewState};

handle_call({send_message_with_files, RoomId, Content, Files}, _From, State) ->
    {Result, NewState} = do_send_message_with_files(RoomId, Content, Files, State),
    {reply, Result, NewState};

handle_call({edit_message, RoomId, EventId, NewContent}, _From, State) ->
    {Result, NewState} = do_edit_message(RoomId, EventId, NewContent, State),
    {reply, Result, NewState};

handle_call({send_reply, RoomId, Content, ReplyEventId}, _From, State) ->
    {Result, NewState} = do_send_reply(RoomId, Content, ReplyEventId, State),
    {reply, Result, NewState};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({register_commands, Names}, State) ->
    Merged = lists:usort(State#state.registered_cmds ++ Names),
    io:format("Matrix: registered commands: ~p~n", [Merged]),
    {noreply, State#state{registered_cmds = Merged}};

handle_cast({mark_encrypted, RoomId}, State) ->
    case sets:is_element(RoomId, State#state.encrypted_rooms) of
        true  -> {noreply, State};
        false ->
            io:format("[matrix] room ~s marked as encrypted~n", [RoomId]),
            Rooms = sets:add_element(RoomId, State#state.encrypted_rooms),
            {noreply, State#state{encrypted_rooms = Rooms}}
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(start_sync, State) ->
    NewState = case do_whoami(State) of
        {ok, UserId, S} ->
            io:format("Matrix bot ready as ~s~n", [UserId]),
            notify_ready(S),
            S;
        {error, Reason} ->
            io:format("Matrix whoami failed: ~p~n", [Reason]),
            State
    end,
    CaughtUpState = case NewState#state.next_batch of
        undefined ->
            io:format("[matrix] first start: catching up to latest event token...~n"),
            case run_catchup_sync(NewState) of
                {ok, NextBatch} ->
                    io:format("[matrix] caught up, starting from ~s~n", [NextBatch]),
                    NewState#state{next_batch = NextBatch};
                {error, Reason2} ->
                    io:format("[matrix] catchup sync failed: ~p, will process history~n",
                              [Reason2]),
                    NewState
            end;
        _ ->
            NewState
    end,
    self() ! do_sync,
    {noreply, CaughtUpState};

handle_info(do_sync, State) ->
    Self = self(),
    spawn_link(fun() ->
        Result = run_sync(State),
        Self ! {sync_result, Result}
    end),
    {noreply, State};

handle_info({sync_result, {ok, NextBatch, Events}}, State) ->
    case length(Events) of
        0 -> ok;
        N -> io:format("[matrix] sync: ~p new event(s)~n", [N])
    end,
    NewState = State#state{next_batch = NextBatch},
    save_next_batch(NextBatch, State#state.homeserver),
    process_events(Events, NewState),
    self() ! do_sync,
    {noreply, NewState};

handle_info({sync_result, {error, Reason}}, State) ->
    io:format("Sync error ~p — retrying in 5s~n", [Reason]),
    erlang:send_after(5000, self(), do_sync),
    {noreply, State};

handle_info({pending_invites, RoomIds}, State) ->
    lists:foreach(fun(RoomId) ->
        case do_join_room(RoomId, State) of
            ok    -> io:format("Joined room ~s~n", [RoomId]);
            Error -> io:format("Failed to join ~s: ~p~n", [RoomId, Error])
        end
    end, RoomIds),
    {noreply, State};

%% Sent from parse_sync_response when m.room.encryption is detected
handle_info({room_encrypted, RoomId}, State) ->
    case sets:is_element(RoomId, State#state.encrypted_rooms) of
        true  -> {noreply, State};
        false ->
            io:format("[matrix] room ~s marked as encrypted (state event)~n", [RoomId]),
            Rooms = sets:add_element(RoomId, State#state.encrypted_rooms),
            {noreply, State#state{encrypted_rooms = Rooms}}
    end;

handle_info({'EXIT', _Pid, normal}, State) ->
    {noreply, State};
handle_info({'EXIT', _Pid, Reason}, State) ->
    io:format("Sync process exited: ~p — retrying in 2s~n", [Reason]),
    erlang:send_after(2000, self(), do_sync),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Matrix Sync
%%%===================================================================

run_sync(#state{token = Token, homeserver = Hostname, next_batch = NextBatch}) ->
    ConnOpts = conn_opts(tls_opts(Hostname)),
    BaseQuery = "?timeout=" ++ ?SYNC_TIMEOUT_S ++ "&filter=" ++ filter_param(),
    Query = case NextBatch of
        undefined -> BaseQuery;
        Batch     -> BaseQuery ++ "&since=" ++ binary_to_list(Batch)
    end,
    AwaitTimeout = ?SYNC_TIMEOUT_MS + 5000,
    with_conn(Hostname, ConnOpts, fun(Conn) ->
        SR = gun:get(Conn, "/_matrix/client/v3/sync" ++ Query, auth_headers(Token)),
        case gun:await(Conn, SR, AwaitTimeout) of
            {response, nofin, 200, _} ->
                case gun:await_body(Conn, SR, AwaitTimeout) of
                    {ok, Body} -> parse_sync_response(Body);
                    Err        -> {error, Err}
                end;
            {response, _, Status, _} -> {error, {status, Status}};
            {error, R}               -> {error, R}
        end
    end).

filter_param() ->
    Filter = #{
        <<"room">> => #{
            <<"timeline">>  => #{
                <<"types">> => [<<"m.room.message">>,
                                <<"m.room.encrypted">>,
                                <<"m.room.encryption">>],
                <<"limit">> => 50
            },
            %% include state so we get m.room.encryption on first sync
            <<"state">>     => #{<<"types">> => [<<"m.room.encryption">>]},
            <<"ephemeral">> => #{<<"types">> => []}
        },
        <<"presence">>  => #{<<"types">> => []},
        <<"to_device">> => #{}
    },
    uri_string:quote(binary_to_list(iolist_to_binary(json:encode(Filter)))).

parse_sync_response(Body) ->
    try
        Data      = json:decode(Body),
        NextBatch = maps:get(<<"next_batch">>, Data),
        Rooms     = maps:get(<<"rooms">>, Data, #{}),
        Join      = maps:get(<<"join">>,   Rooms, #{}),
        Invite    = maps:get(<<"invite">>, Rooms, #{}),
        case map_size(Invite) > 0 of
            true  -> ?MODULE ! {pending_invites, maps:keys(Invite)};
            false -> ok
        end,
        ToDevice = maps:get(<<"to_device">>, Data, #{}),
        ToDeviceEvents = maps:get(<<"events">>, ToDevice, []),
        case length(ToDeviceEvents) > 0 of
            true ->
                io:format("[matrix] ~p to-device event(s) received: ~p~n",
                          [length(ToDeviceEvents),
                           [maps:get(<<"type">>, E, <<>>) || E <- ToDeviceEvents]]),
                case whereis(matrix_e2e) of
                    undefined -> ok;
                    _         -> matrix_e2e:handle_to_device(ToDeviceEvents)
                end;
            false ->
                io:format("[matrix] no to-device events in this sync~n")
        end,
        Events = maps:fold(fun(RoomId, RoomData, Acc) ->
            %% Detect encryption from state events (included on first sync)
            StateEvts = maps:get(<<"events">>,
                                 maps:get(<<"state">>, RoomData, #{}), []),
            lists:foreach(fun(SE) ->
                case maps:get(<<"type">>, SE, <<>>) of
                    <<"m.room.encryption">> -> ?MODULE ! {room_encrypted, RoomId};
                    _                       -> ok
                end
            end, StateEvts),
            Timeline = maps:get(<<"timeline">>, RoomData, #{}),
            Evts     = maps:get(<<"events">>,   Timeline,  []),
            [{RoomId, E} || E <- Evts] ++ Acc
        end, [], Join),
        {ok, NextBatch, Events}
    catch C:R ->
        {error, {parse_error, C, R}}
    end.

%%%===================================================================
%%% Event Processing
%%%===================================================================

do_join_room(RoomId, #state{token = Token, homeserver = Hostname}) ->
    ConnOpts = conn_opts(tls_opts(Hostname)),
    URL = "/_matrix/client/v3/join/" ++ uri_string:quote(binary_to_list(RoomId)),
    with_conn(Hostname, ConnOpts, fun(Conn) ->
        Headers = auth_headers(Token) ++ [{<<"content-type">>, <<"application/json">>}],
        SR = gun:post(Conn, URL, Headers, <<"{}">>),
        case gun:await(Conn, SR, ?CONNECTION_TIMEOUT) of
            {response, nofin, Status, _} when Status >= 200, Status < 300 ->
                gun:await_body(Conn, SR, ?CONNECTION_TIMEOUT),
                ok;
            {response, nofin, Status, _} ->
                {ok, Rb} = gun:await_body(Conn, SR, ?CONNECTION_TIMEOUT),
                {error, {status, Status, Rb}};
            {error, R} -> {error, R}
        end
    end).

process_events(Events, State) ->
    BotUserId = State#state.bot_user_id,
    io:format("[matrix] process_events: ~p event(s) received~n", [length(Events)]),
    lists:foreach(fun({RoomId, Event}) ->
        Sender  = maps:get(<<"sender">>,   Event, <<>>),
        Content = maps:get(<<"content">>,  Event, #{}),
        EventId = maps:get(<<"event_id">>, Event, <<>>),
        EvtType = maps:get(<<"type">>,     Event, <<>>),
        MsgType = maps:get(<<"msgtype">>,  Content, <<>>),
        Body    = maps:get(<<"body">>,     Content, <<>>),
        %% Detect room encryption from timeline state events
        case EvtType of
            <<"m.room.encryption">> ->
                gen_server:cast(?MODULE, {mark_encrypted, RoomId});
            _ -> ok
        end,
        io:format("[matrix] event from=~s room=~s type=~s~n", [Sender, RoomId, MsgType]),
        case Sender =:= BotUserId of
            true  ->
                io:format("[matrix] skipping own message~n");
            false ->
                case MsgType of
                    <<"m.text">> ->
                        io:format("[matrix] dispatching message: ~s~n", [Body]),
                        Author = #{<<"id">> => Sender, <<"username">> => Sender},
                        dispatch_message(Body, RoomId, EventId, Author, State);
                    _ ->
                        Algo = maps:get(<<"algorithm">>, Content, <<>>),
                        case {MsgType, Algo} of
                            {<<>>, <<"m.megolm.v1.aes-sha2">>} ->
                                %% Receiving an encrypted event confirms room is E2E
                                gen_server:cast(?MODULE, {mark_encrypted, RoomId}),
                                io:format("[matrix] encrypted event in ~s, attempting decrypt~n",
                                          [RoomId]),
                                try_decrypt_and_dispatch(Event, RoomId, EventId, Sender, State);
                            _ ->
                                io:format("[matrix] ignoring event type=~s algo=~s~n",
                                          [MsgType, Algo])
                        end
                end
        end
    end, Events).

dispatch_message(<<"!", Rest/binary>>, RoomId, EventId, Author, State) ->
    {CmdName, Options} = parse_command(Rest),
    io:format("[matrix] slash command: !~s from ~s in ~s~n",
              [CmdName, maps:get(<<"id">>, Author, <<>>), RoomId]),
    case State#state.command_handler of
        undefined ->
            io:format("[matrix] no command_handler set, ignoring~n");
        Handler ->
            %% spawn: avoids calling_self deadlock when handler calls send_message/3
            spawn(fun() ->
                invoke_slash(Handler, CmdName, Options, RoomId, EventId, Author,
                             State#state.token)
            end)
    end;
dispatch_message(Body, RoomId, _EventId, Author, State) ->
    io:format("[matrix] message from ~s in ~s: ~s~n",
              [maps:get(<<"id">>, Author, <<>>), RoomId, Body]),
    case State#state.command_handler of
        undefined ->
            io:format("[matrix] no command_handler set, ignoring~n");
        Handler ->
            %% spawn: avoids calling_self deadlock when handler calls send_message/3
            spawn(fun() ->
                invoke_message(Handler, Body, RoomId, Author, State#state.token)
            end)
    end.

try_decrypt_and_dispatch(Event, RoomId, EventId, Sender, State) ->
    case whereis(matrix_e2e) of
        undefined ->
            io:format("[matrix] matrix_e2e not running, cannot decrypt~n");
        _ ->
            case matrix_e2e:decrypt_room_event(Event#{<<"room_id">> => RoomId}) of
                {ok, Decrypted} ->
                    Body    = maps:get(<<"body">>,    maps:get(<<"content">>, Decrypted, #{}), <<>>),
                    MsgType = maps:get(<<"msgtype">>, maps:get(<<"content">>, Decrypted, #{}), <<>>),
                    io:format("[matrix] decrypted event type=~s body=~s~n", [MsgType, Body]),
                    case MsgType of
                        <<"m.text">> ->
                            Author = #{<<"id">> => Sender, <<"username">> => Sender},
                            dispatch_message(Body, RoomId, EventId, Author, State);
                        _ ->
                            io:format("[matrix] ignoring decrypted non-text type: ~s~n", [MsgType])
                    end;
                {error, no_session} ->
                    Content   = maps:get(<<"content">>, Event, #{}),
                    SessionId = maps:get(<<"session_id">>, Content, <<>>),
                    SenderKey = maps:get(<<"sender_key">>, Content, <<>>),
                    io:format("[matrix] no megolm session yet for room ~s, requesting key~n",
                              [RoomId]),
                    matrix_e2e:request_room_key(RoomId, SessionId, SenderKey);
                {error, Reason} ->
                    io:format("[matrix] decrypt failed: ~p~n", [Reason])
            end
    end.

parse_command(Rest) ->
    case binary:split(Rest, <<" ">>, [global, trim_all]) of
        []           -> {<<>>, []};
        [Cmd]        -> {Cmd, []};
        [Cmd | Args] ->
            Options = [#{<<"name">> => <<"args">>, <<"value">> => A} || A <- Args],
            {Cmd, Options}
    end.

%%%===================================================================
%%% Handler Dispatch
%%%===================================================================

invoke_message(Handler, Content, RoomId, Author, Token) when is_atom(Handler) ->
    catch_handler(fun() -> Handler:handle_message(Content, RoomId, Author, Token) end,
                  handle_message, Handler);
invoke_message({Mod, Fun}, Content, RoomId, Author, Token) ->
    catch_handler(fun() -> Mod:Fun(Content, RoomId, Author, Token) end, Fun, Mod);
invoke_message(Fun, Content, RoomId, Author, Token) when is_function(Fun, 4) ->
    catch_handler(fun() -> Fun(Content, RoomId, Author, Token) end, fun_handler, anonymous).

invoke_slash(Handler, Cmd, Opts, RoomId, EventId, User, Token) when is_atom(Handler) ->
    catch_handler(fun() -> Handler:handle_slash_command(Cmd, Opts, RoomId, EventId, User, Token) end,
                  handle_slash_command, Handler);
invoke_slash({Mod, Fun}, Cmd, Opts, RoomId, EventId, User, Token) ->
    catch_handler(fun() -> Mod:Fun(Cmd, Opts, RoomId, EventId, User, Token) end, Fun, Mod);
invoke_slash(Fun, Cmd, Opts, RoomId, EventId, User, Token) when is_function(Fun, 6) ->
    catch_handler(fun() -> Fun(Cmd, Opts, RoomId, EventId, User, Token) end, fun_handler, anonymous).

catch_handler(F, FunName, Module) ->
    try F()
    catch C:R:Stack ->
        io:format("Handler ~p:~p error ~p:~p~n~p~n", [Module, FunName, C, R, Stack])
    end.

notify_ready(#state{command_handler = undefined}) -> ok;
notify_ready(#state{command_handler = Handler, token = Token}) when is_atom(Handler) ->
    catch Handler:on_ready(Token);
notify_ready(_) -> ok.

%%%===================================================================
%%% Matrix REST helpers
%%%===================================================================

do_whoami(State = #state{token = Token, homeserver = Hostname}) ->
    ConnOpts = conn_opts(tls_opts(Hostname)),
    with_conn(Hostname, ConnOpts, fun(Conn) ->
        SR = gun:get(Conn, "/_matrix/client/v3/account/whoami", auth_headers(Token)),
        case gun:await(Conn, SR, ?CONNECTION_TIMEOUT) of
            {response, nofin, 200, _} ->
                {ok, Body} = gun:await_body(Conn, SR, ?CONNECTION_TIMEOUT),
                UserId = maps:get(<<"user_id">>, json:decode(Body)),
                {ok, UserId, State#state{bot_user_id = UserId}};
            {response, _, Status, _} -> {error, {status, Status}};
            {error, R}               -> {error, R}
        end
    end).

%%%===================================================================
%%% Message Sending — routes through E2E for encrypted rooms
%%%===================================================================

do_send_message(RoomId, Content, State) ->
    case sets:is_element(RoomId, State#state.encrypted_rooms) of
        true  -> do_send_message_encrypted(RoomId, Content, State);
        false -> do_send_message_plain(RoomId, Content, State)
    end.

%% Plain path — unchanged behaviour
do_send_message_plain(RoomId, Content, State = #state{txn_id = TxnId}) ->
    Body = #{<<"msgtype">> => <<"m.text">>, <<"body">> => to_binary(Content)},
    case matrix_put(State#state.homeserver, room_send_url(RoomId, TxnId),
                    State#state.token, Body) of
        {ok, RespBody} ->
            EventId = maps:get(<<"event_id">>, json:decode(RespBody), <<>>),
            {{ok, EventId}, State#state{txn_id = TxnId + 1}};
        Err ->
            {Err, State#state{txn_id = TxnId + 1}}
    end.

%% Encrypted path — wraps plaintext with matrix_e2e:encrypt_room_event/2
do_send_message_encrypted(RoomId, Content, State = #state{txn_id = TxnId}) ->
    case whereis(matrix_e2e) of
        undefined ->
            io:format("[matrix] matrix_e2e not running, falling back to plaintext~n"),
            do_send_message_plain(RoomId, Content, State);
        _ ->
            InnerEvent = #{
                <<"type">>    => <<"m.room.message">>,
                <<"content">> => #{
                    <<"msgtype">> => <<"m.text">>,
                    <<"body">>    => to_binary(Content)
                },
                <<"room_id">> => RoomId
            },
            case matrix_e2e:encrypt_room_event(RoomId, InnerEvent) of
                {ok, EncContent} ->
                    URL = room_send_url_type(RoomId, TxnId, <<"m.room.encrypted">>),
                    case matrix_put(State#state.homeserver, URL,
                                    State#state.token, EncContent) of
                        {ok, RespBody} ->
                            EventId = maps:get(<<"event_id">>, json:decode(RespBody), <<>>),
                            {{ok, EventId}, State#state{txn_id = TxnId + 1}};
                        Err ->
                            {Err, State#state{txn_id = TxnId + 1}}
                    end;
                {error, Reason} ->
                    io:format("[matrix] E2E encrypt failed (~p), falling back to plaintext~n",
                              [Reason]),
                    do_send_message_plain(RoomId, Content, State)
            end
    end.

do_send_reply(RoomId, Content, ReplyEventId, State = #state{txn_id = TxnId}) ->
    Body = #{
        <<"msgtype">>      => <<"m.text">>,
        <<"body">>         => to_binary(Content),
        <<"m.relates_to">> => #{
            <<"m.in_reply_to">> => #{<<"event_id">> => ReplyEventId}
        }
    },
    case matrix_put(State#state.homeserver, room_send_url(RoomId, TxnId),
                    State#state.token, Body) of
        {ok, RespBody} ->
            EventId = maps:get(<<"event_id">>, json:decode(RespBody), <<>>),
            {{ok, EventId}, State#state{txn_id = TxnId + 1}};
        Err ->
            {Err, State#state{txn_id = TxnId + 1}}
    end.

do_send_message_with_files(RoomId, Content, Files, State) ->
    {State1, MxcUris} = lists:foldl(fun({Filename, Data}, {S, Uris}) ->
        case upload_file(Filename, Data, S) of
            {ok, MxcUri, S2} -> {S2, [MxcUri | Uris]};
            {error, _}       -> {S, Uris}
        end
    end, {State, []}, Files),
    {TextResult, State2} = do_send_message(RoomId, Content, State1),
    State3 = lists:foldl(fun({MxcUri, {Filename, _}}, S) ->
        FileBody = #{
            <<"msgtype">> => <<"m.file">>,
            <<"body">>    => Filename,
            <<"url">>     => MxcUri
        },
        case matrix_put(S#state.homeserver, room_send_url(RoomId, S#state.txn_id),
                        S#state.token, FileBody) of
            _ -> S#state{txn_id = S#state.txn_id + 1}
        end
    end, State2, lists:zip(lists:reverse(MxcUris), Files)),
    {TextResult, State3}.

do_edit_message(RoomId, EventId, NewContent, State = #state{txn_id = TxnId}) ->
    Body = #{
        <<"msgtype">> => <<"m.text">>,
        <<"body">>    => <<"* ", (to_binary(NewContent))/binary>>,
        <<"m.new_content">> => #{
            <<"msgtype">> => <<"m.text">>,
            <<"body">>    => to_binary(NewContent)
        },
        <<"m.relates_to">> => #{
            <<"rel_type">> => <<"m.replace">>,
            <<"event_id">> => EventId
        }
    },
    case matrix_put(State#state.homeserver, room_send_url(RoomId, TxnId),
                    State#state.token, Body) of
        {ok, RespBody} ->
            NewEventId = maps:get(<<"event_id">>, json:decode(RespBody), <<>>),
            {{ok, 200, NewEventId}, State#state{txn_id = TxnId + 1}};
        {error, {status, Status, Resp}} ->
            {{ok, Status, Resp}, State#state{txn_id = TxnId + 1}};
        Err ->
            {Err, State#state{txn_id = TxnId + 1}}
    end.

upload_file(Filename, Data, State = #state{token = Token, homeserver = Hostname,
                                            txn_id = TxnId}) ->
    ConnOpts = conn_opts(tls_opts(Hostname)),
    URL = "/_matrix/media/v3/upload?filename=" ++ uri_string:quote(binary_to_list(Filename)),
    Headers = auth_headers(Token) ++ [{<<"content-type">>, <<"application/octet-stream">>}],
    Result = with_conn(Hostname, ConnOpts, fun(Conn) ->
        SR = gun:post(Conn, URL, Headers, Data),
        case gun:await(Conn, SR, ?CONNECTION_TIMEOUT) of
            {response, nofin, 200, _} ->
                {ok, Body} = gun:await_body(Conn, SR, ?CONNECTION_TIMEOUT),
                {ok, maps:get(<<"content_uri">>, json:decode(Body))};
            {response, _, Status, _} -> {error, {status, Status}};
            {error, R}               -> {error, R}
        end
    end),
    case Result of
        {ok, MxcUri} -> {ok, MxcUri, State#state{txn_id = TxnId + 1}};
        Err          -> Err
    end.

%%%===================================================================
%%% Catchup sync & next_batch persistence
%%%===================================================================

run_catchup_sync(#state{token = Token, homeserver = Hostname}) ->
    ConnOpts = conn_opts(tls_opts(Hostname)),
    Query = "?timeout=0&filter=" ++ filter_param(),
    with_conn(Hostname, ConnOpts, fun(Conn) ->
        SR = gun:get(Conn, "/_matrix/client/v3/sync" ++ Query, auth_headers(Token)),
        case gun:await(Conn, SR, 30000) of
            {response, nofin, 200, _} ->
                case gun:await_body(Conn, SR, 30000) of
                    {ok, Body} ->
                        Data = json:decode(Body),
                        {ok, maps:get(<<"next_batch">>, Data)};
                    Err -> {error, Err}
                end;
            {response, _, Status, _} -> {error, {status, Status}};
            {error, R}               -> {error, R}
        end
    end).

-spec batch_file(string()) -> string().
batch_file(Hostname) ->
    "matrix_next_batch_" ++ Hostname ++ ".bin".

save_next_batch(NextBatch, Hostname) ->
    file:write_file(batch_file(Hostname), NextBatch).

load_next_batch(Hostname) ->
    case file:read_file(batch_file(Hostname)) of
        {ok, Batch} ->
            io:format("[matrix] resuming from saved next_batch token~n"),
            Batch;
        _ ->
            undefined
    end.


%%%===================================================================
%%% HTTP helpers
%%%===================================================================

matrix_put(Hostname, URL, Token, Body) ->
    ConnOpts = conn_opts(tls_opts(Hostname)),
    Payload  = iolist_to_binary(json:encode(Body)),
    Headers  = auth_headers(Token) ++ [{<<"content-type">>, <<"application/json">>}],
    with_conn(Hostname, ConnOpts, fun(Conn) ->
        SR = gun:put(Conn, URL, Headers, Payload),
        case gun:await(Conn, SR, ?CONNECTION_TIMEOUT) of
            {response, nofin, Status, _} when Status >= 200, Status < 300 ->
                {ok, RespBody} = gun:await_body(Conn, SR, ?CONNECTION_TIMEOUT),
                {ok, RespBody};
            {response, nofin, Status, _} ->
                {ok, Rb} = gun:await_body(Conn, SR, ?CONNECTION_TIMEOUT),
                {error, {status, Status, Rb}};
            {error, R} -> {error, R}
        end
    end).

with_conn(Hostname, ConnOpts, F) ->
    case gun:open(Hostname, 443, ConnOpts) of
        {ok, Conn} ->
            Result = case gun:await_up(Conn, ?CONNECTION_TIMEOUT) of
                {ok, _} -> F(Conn);
                {error, R} -> {error, R}
            end,
            gun:close(Conn),
            Result;
        {error, R} -> {error, R}
    end.

%%%===================================================================
%%% Utilities
%%%===================================================================

room_send_url(RoomId, TxnId) ->
    room_send_url_type(RoomId, TxnId, <<"m.room.message">>).

room_send_url_type(RoomId, TxnId, Type) ->
    "/_matrix/client/v3/rooms/" ++
    uri_string:quote(binary_to_list(RoomId)) ++
    "/send/" ++
    binary_to_list(Type) ++ "/" ++
    integer_to_list(TxnId).

auth_headers(Token) ->
    [{<<"authorization">>, <<"Bearer ", Token/binary>>}].

tls_opts(Hostname) ->
    [{verify, verify_peer},
     {cacerts, certifi:cacerts()},
     {server_name_indication, Hostname},
     {customize_hostname_check,
      [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}].

conn_opts(TLSOpts) ->
    #{transport       => tls,
      tls_opts        => TLSOpts,
      protocols       => [http],
      connect_timeout => ?CONNECTION_TIMEOUT,
      http_opts       => #{keepalive => infinity}}.

extract_hostname("https://" ++ Rest) -> hd(string:split(Rest, "/"));
extract_hostname("http://"  ++ Rest) -> hd(string:split(Rest, "/"));
extract_hostname(Other)              -> Other.

get_env_or_default(Var, Default) ->
    case os:getenv(Var) of
        V when V =:= false; V =:= "" -> Default;
        V -> V
    end.

to_binary(B) when is_binary(B) -> B;
to_binary(L) when is_list(L)   -> list_to_binary(L).
