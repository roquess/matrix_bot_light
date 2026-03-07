%%%===================================================================
%%% Matrix Bot Light Application
%%% Reads MATRIX_TOKEN and optionally MATRIX_HOMESERVER from env
%%%===================================================================
-module(matrix_bot_light_app).
-behaviour(application).

-export([start/2, stop/1]).
-export([get_bot_pid/0, is_bot_running/0]).

-define(DEFAULT_HOMESERVER, "https://matrix.roques.me").

%%%===================================================================
%%% Application callbacks
%%%===================================================================

start(_StartType, _StartArgs) ->
    io:format("Starting Matrix Bot Light Application...~n"),
    case os:getenv("MATRIX_TOKEN") of
        Token when Token =:= false; Token =:= "" ->
            io:format("Error: MATRIX_TOKEN environment variable is not set or empty~n"),
            {error, no_token};
        Token ->
            Homeserver = get_env_or_default("MATRIX_HOMESERVER", ?DEFAULT_HOMESERVER),
            io:format("Connecting to homeserver: ~s~n", [Homeserver]),
            Options = get_bot_options(),
            case matrix_bot_light_sup:start_link(Token, Homeserver, Options) of
                {ok, Pid} ->
                    io:format("Matrix bot supervisor started: ~p~n", [Pid]),
                    {ok, Pid};
                {error, Reason} ->
                    io:format("Failed to start Matrix bot supervisor: ~p~n", [Reason]),
                    {error, Reason}
            end
    end.

stop(_State) ->
    io:format("Stopping Matrix Bot Light Application...~n"),
    ok.

%%%===================================================================
%%% Public utility functions
%%%===================================================================

-spec get_bot_pid() -> {ok, pid()} | {error, not_found}.
get_bot_pid() ->
    matrix_bot_light_sup:get_bot_status().

-spec is_bot_running() -> boolean().
is_bot_running() ->
    case get_bot_pid() of
        {ok, _}    -> true;
        {error, _} -> false
    end.

%%%===================================================================
%%% Private
%%%===================================================================

-spec get_env_or_default(string(), string()) -> string().
get_env_or_default(Var, Default) ->
    case os:getenv(Var) of
        V when V =:= false; V =:= "" -> Default;
        V -> V
    end.

-spec get_bot_options() -> list().
get_bot_options() ->
    Base = case application:get_env(matrix_bot_light, command_handler) of
        {ok, Handler} -> [{command_handler, Handler}];
        undefined     -> []
    end,
    case os:getenv("MATRIX_COMMAND_HANDLER") of
        V when V =:= false; V =:= "" ->
            Base;
        HandlerStr ->
            try
                Handler2 = list_to_existing_atom(HandlerStr),
                lists:keystore(command_handler, 1, Base, {command_handler, Handler2})
            catch _:_ ->
                Base
            end
    end.
