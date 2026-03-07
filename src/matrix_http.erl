%%%===================================================================
%%% matrix_http.erl — Internal HTTP helper used by matrix_e2e
%%%===================================================================
-module(matrix_http).
-export([post/4, put/4, get/3]).

-define(TIMEOUT, 30000).

-spec post(string(), string(), binary() | string(), map()) ->
        {ok, binary()} | {error, term()}.
post(Hostname, Path, Token, Body) ->
    request(post, Hostname, Path, Token, Body).

-spec put(string(), string(), binary() | string(), map()) ->
        {ok, binary()} | {error, term()}.
put(Hostname, Path, Token, Body) ->
    request(put, Hostname, Path, Token, Body).

-spec get(string(), string(), binary() | string()) ->
        {ok, binary()} | {error, term()}.
get(Hostname, Path, Token) ->
    request(get, Hostname, Path, Token, undefined).

%%%===================================================================
%%% Internal
%%%===================================================================

request(Method, Hostname, Path, Token, Body) ->
    TLSOpts  = [{verify, verify_peer},
                {cacerts, certifi:cacerts()},
                {server_name_indication, Hostname},
                {customize_hostname_check,
                 [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}],
    ConnOpts = #{transport       => tls,
                 tls_opts        => TLSOpts,
                 protocols       => [http],
                 connect_timeout => ?TIMEOUT},
    BinToken = to_binary(Token),
    Headers  = [{<<"authorization">>, <<"Bearer ", BinToken/binary>>},
                {<<"content-type">>,  <<"application/json">>}],
    case gun:open(Hostname, 443, ConnOpts) of
        {ok, Conn} ->
            Result = case gun:await_up(Conn, ?TIMEOUT) of
                {ok, _} ->
                    SR = case {Method, Body} of
                        {post, undefined} -> gun:post(Conn, Path, Headers, <<"{}">>);
                        {post, B}         -> gun:post(Conn, Path, Headers,
                                                      iolist_to_binary(json:encode(B)));
                        {put,  B}         -> gun:put(Conn, Path, Headers,
                                                     iolist_to_binary(json:encode(B)));
                        {get,  _}         -> gun:get(Conn, Path, Headers)
                    end,
                    case gun:await(Conn, SR, ?TIMEOUT) of
                        {response, nofin, Status, _} when Status < 300 ->
                            case gun:await_body(Conn, SR, ?TIMEOUT) of
                                {ok, Resp} -> {ok, Resp};
                                E          -> E
                            end;
                        {response, nofin, Status, _} ->
                            {ok, RB} = gun:await_body(Conn, SR, ?TIMEOUT),
                            {error, {status, Status, RB}};
                        {error, R} -> {error, R}
                    end;
                {error, R} -> {error, R}
            end,
            gun:close(Conn),
            Result;
        {error, R} -> {error, R}
    end.

to_binary(B) when is_binary(B) -> B;
to_binary(L) when is_list(L)   -> list_to_binary(L).
