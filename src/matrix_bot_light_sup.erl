%%%===================================================================
%%% Matrix Bot Light Supervisor
%%%===================================================================
-module(matrix_bot_light_sup).
-behaviour(supervisor).

-export([start_link/3, get_bot_status/0, restart_bot/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

-spec start_link(string(), string(), list()) -> {ok, pid()} | {error, term()}.
start_link(Token, Homeserver, Options) ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, [Token, Homeserver, Options]).

-spec get_bot_status() -> {ok, pid()} | {error, not_found}.
get_bot_status() ->
    case whereis(matrix_bot_light_client) of
        undefined -> {error, not_found};
        Pid       ->
            case is_process_alive(Pid) of
                true  -> {ok, Pid};
                false -> {error, not_found}
            end
    end.

-spec restart_bot() -> ok | {error, term()}.
restart_bot() ->
    case supervisor:terminate_child(?SERVER, matrix_bot_light_client) of
        ok ->
            case supervisor:restart_child(?SERVER, matrix_bot_light_client) of
                {ok, _}    -> ok;
                {ok, _, _} -> ok;
                Err        -> Err
            end;
        Err -> Err
    end.

init([Token, Homeserver, Options]) ->
    SupFlags = #{strategy => one_for_one, intensity => 5, period => 60},
    ChildSpecs = [
        #{
            id       => matrix_e2e,
            start    => {matrix_e2e, start_link, [Token, Homeserver]},
            restart  => transient,
            shutdown => 10000,
            type     => worker,
            modules  => [matrix_e2e]
        },
        #{
            id       => matrix_bot_light_client,
            start    => {matrix_bot_light_client, start_link, [Token, Homeserver, Options]},
            restart  => transient,
            shutdown => 10000,
            type     => worker,
            modules  => [matrix_bot_light_client]
        }
    ],
    io:format("Matrix bot supervisor initialized~n"),
    {ok, {SupFlags, ChildSpecs}}.
