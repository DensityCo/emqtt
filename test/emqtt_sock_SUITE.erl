%%--------------------------------------------------------------------
%% Copyright (c) 2020 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emqtt_sock_SUITE).

-compile(nowarn_export_all).
-compile(export_all).

-include_lib("eunit/include/eunit.hrl").
-include_lib("common_test/include/ct.hrl").

all() -> emqtt_test_lib:all(?MODULE) ++ [{group, all}].

groups() ->
    [ {all, [ {group, unknown_ca}
            , {group, known_ca}
            ]}
    , {unknown_ca, [ {group, server}
                   , {group, wildcard_server}
                   ]}
    , {known_ca, [ {group, server}
                 , {group, wildcard_server}
                 ]}
    , {server, [ {group, server_verify_peer}
               , {group, server_verify_none}
               ]}
    , {wildcard_server, [ {group, server_verify_peer}
                        , {group, server_verify_none}
                        ]}
    , {server_verify_peer, [ {group, client_verify_peer}
                           , {group, client_verify_none}
                           ]}
    , {server_verify_none, [ {group, client_verify_peer}
                           , {group, client_verify_none}
                           ]}
    , {client_verify_peer, [gen_connect_test]}
    , {client_verify_none, [gen_connect_test]}
    , {tlsv13, [tlsv13_connect_test]}
    ].

init_per_group(all, Config) ->
    Config;
init_per_group(unknown_ca, Config) ->
    [{is_same_ca, false} | Config];
init_per_group(known_ca, Config) ->
    [{is_same_ca, true} | Config];
init_per_group(client_verify_peer, Config) ->
    [{client_verify, verify_peer} | Config];
init_per_group(client_verify_none, Config) ->
    [{client_verify, verify_none} | Config];
init_per_group(wildcard_server, Config) ->
    [{is_wildcard_server, true} | Config];
init_per_group(server, Config) ->
    [{is_wildcard_server, false} | Config];
init_per_group(server_verify_peer, Config) ->
    [{server_verify, verify_peer} | Config];
init_per_group(server_verify_none, Config) ->
    [{server_verify, verify_none} | Config].

end_per_group(all, Config) ->
    Config;
end_per_group(unknown_ca, Config) ->
    proplists:delete(is_same_ca, Config);
end_per_group(known_ca, Config) ->
    proplists:delete(is_same_ca, Config);
end_per_group(client_verify_peer, Config) ->
    proplists:delete(client_verify, Config);
end_per_group(client_verify_none, Config) ->
    proplists:delete(client_verify, Config);
end_per_group(wildcard_server, Config) ->
    proplists:delete(is_wildcard_server, Config);
end_per_group(server, Config) ->
    proplists:delete(is_wildcard_server, Config);
end_per_group(server_verify_peer, Config) ->
    proplists:delete(server_verify, Config);
end_per_group(server_verify_none, Config) ->
    proplists:delete(server_verify, Config).


init_per_suite(Config) ->
    emqtt_test_lib:ensure_test_module(emqx_common_test_helpers),
    DataDir = cert_dir(Config),
    _ = emqtt_test_lib:gen_ca(DataDir, "ca"),
    _ = emqtt_test_lib:gen_host_cert("wildcard.localhost", "ca", DataDir, true),
    _ = emqtt_test_lib:gen_host_cert("localhost", "ca", DataDir),
    _ = emqtt_test_lib:gen_host_cert("client", "ca", DataDir),
    _ = emqtt_test_lib:gen_ca(DataDir, "other-ca"),
    _ = emqtt_test_lib:gen_host_cert("other-client", "other-ca", DataDir),

    [ %% Clients
      {unknown_client_cert_files, [{cacertfile, emqtt_test_lib:ca_cert_name(DataDir, "other-ca")},
                                   {keyfile,  emqtt_test_lib:key_name(DataDir, "other-client")},
                                   {certfile,  emqtt_test_lib:cert_name(DataDir, "other-client")},
                                   {server_name_indication, true}
                                  ]}
    , {known_client_cert_files, [{cacertfile, emqtt_test_lib:ca_cert_name(DataDir, "ca")},
                                 {keyfile,  emqtt_test_lib:key_name(DataDir, "client")},
                                 {certfile,  emqtt_test_lib:cert_name(DataDir, "client")},
                                 {server_name_indication, true}
                                ]}
      %% Servers
    , {wildcard_server_cert_files, [{cacertfile, emqtt_test_lib:ca_cert_name(DataDir, "ca")},
                                    {keyfile,  emqtt_test_lib:key_name(DataDir, "wildcard.localhost")},
                                    {certfile,  emqtt_test_lib:cert_name(DataDir, "wildcard.localhost")}
                                   ]}
    , {common_server_cert_files, [{cacertfile, emqtt_test_lib:ca_cert_name(DataDir, "ca")},
                                  {keyfile,  emqtt_test_lib:key_name(DataDir, "localhost")},
                                  {certfile,  emqtt_test_lib:cert_name(DataDir, "localhost")}
                                 ]}
    | Config].

end_per_suite(_Config) ->
    ok.

init_per_testcase(gen_connect_test, Config) ->
    ServerVerify = ?config(server_verify, Config),
    ClientVerify = ?config(client_verify, Config),
    IsWildcard = ?config(is_wildcard_server, Config),
    IsSameCA = ?config(is_same_ca, Config),

    ServerFiles = case IsWildcard of
                      true -> ?config(wildcard_server_cert_files , Config);
                      false -> ?config(common_server_cert_files, Config)
                  end,

    ClientFiles = case IsSameCA of
                      true -> ?config(known_client_cert_files , Config);
                      false -> ?config(unknown_client_cert_files, Config)
                  end,

    IsPass = if ClientVerify =:= verify_none andalso ServerVerify =:= verify_none -> true;
                ClientVerify =:= verify_peer andalso IsSameCA -> true;
                ClientVerify =:= verify_none andalso not IsSameCA -> false;
                ServerVerify =:= verify_peer andalso IsSameCA -> true;
                ServerVerify =:= verify_peer andalso not IsSameCA -> false;
                true -> false
             end,
    [ {server_ssl_opts, [ {verify, ServerVerify} | ServerFiles]}
    , {client_ssl_opts, [ {verify, ClientVerify} | ClientFiles]}
    , {target_host, case IsWildcard of
                        true -> "a.wildcard.localhost";
                        false -> "localhost"
                    end}
    , {expect_pass, IsPass}
     | Config];
init_per_testcase(tlsv13_connect_test, Config) ->
    ServerFiles = ?config(common_server_cert_files, Config),
    ClientFiles = ?config(known_client_cert_files , Config),
    [ {server_ssl_opts, [{verify, verify_peer}, {versions, ['tlsv1.3']} | ServerFiles]}
    , {client_ssl_opts, [{verify, verify_peer}, {versions, ['tlsv1.3']} | ClientFiles]}
    , {target_host, "localhost"}
     | Config];
init_per_testcase(_, Config) ->
    Config.

%%--------------------------------------------------------------------
%% Test cases
%%--------------------------------------------------------------------

t_tcp_sock(_) ->
    Server = tcp_server:start_link(4001),
    {ok, Sock} = emqtt_sock:connect("127.0.0.1", 4001, [], 3000),
    send_and_recv_with(Sock),
    ok = emqtt_sock:close(Sock),
    ok = tcp_server:stop(Server).

t_http_proxy_tunnel(_) ->
    BackendPort = 14001,
    Backend = tcp_server:start_link(BackendPort),
    ProxyPort = 14080,
    Proxy = start_http_proxy(ProxyPort,
                fun(_Host, _Port) -> {forward, "127.0.0.1", BackendPort} end),
    ProxyOpts = #{host => "127.0.0.1", port => ProxyPort},
    {ok, Sock} = emqtt_sock:connect("backend.example.com", BackendPort,
                                    [{proxy, ProxyOpts}], 3000),
    ok = emqtt_sock:send(Sock, <<"hi">>),
    {ok, <<"hi">>} = emqtt_sock:recv(Sock, 0),
    ok = emqtt_sock:close(Sock),
    stop_http_proxy(Proxy),
    ok = tcp_server:stop(Backend).

t_http_proxy_auth(_) ->
    BackendPort = 14002,
    Backend = tcp_server:start_link(BackendPort),
    ProxyPort = 14081,
    ExpectedAuth = <<"Basic ", (base64:encode(<<"u:p">>))/binary>>,
    Proxy = start_http_proxy(ProxyPort,
                fun(_, _) -> {forward_if_auth, ExpectedAuth, "127.0.0.1", BackendPort} end),
    ProxyOpts = #{host => <<"127.0.0.1">>, port => ProxyPort,
                  username => <<"u">>, password => <<"p">>},
    {ok, Sock} = emqtt_sock:connect("backend.example.com", BackendPort,
                                    [{proxy, ProxyOpts}], 3000),
    ok = emqtt_sock:send(Sock, <<"hello">>),
    {ok, <<"hello">>} = emqtt_sock:recv(Sock, 0),
    ok = emqtt_sock:close(Sock),
    stop_http_proxy(Proxy),
    ok = tcp_server:stop(Backend).

t_http_proxy_rejected(_) ->
    ProxyPort = 14082,
    Proxy = start_http_proxy(ProxyPort, fun(_, _) -> reject end),
    ProxyOpts = #{host => "127.0.0.1", port => ProxyPort},
    Res = emqtt_sock:connect("backend.example.com", 1883,
                             [{proxy, ProxyOpts}], 3000),
    ?assertMatch({error, {proxy_error, {proxy_status, 407, _}}}, Res),
    stop_http_proxy(Proxy).

t_http_proxy_unreachable(_) ->
    ProxyOpts = #{host => "127.0.0.1", port => 1},
    Res = emqtt_sock:connect("backend.example.com", 1883,
                             [{proxy, ProxyOpts}], 1000),
    ?assertMatch({error, {proxy_connect_error, _}}, Res).

%% Minimal HTTP CONNECT proxy for tests
start_http_proxy(Port, Handler) ->
    Parent = self(),
    Pid = spawn_link(fun() ->
                {ok, LSock} = gen_tcp:listen(Port, [binary, {active, false},
                                                    {reuseaddr, true}, {packet, http_bin}]),
                Parent ! {self(), ready},
                proxy_loop(LSock, Handler)
        end),
    receive {Pid, ready} -> Pid after 2000 -> error(proxy_not_ready) end.

stop_http_proxy(Pid) ->
    unlink(Pid),
    exit(Pid, kill),
    ok.

proxy_loop(LSock, Handler) ->
    case gen_tcp:accept(LSock) of
        {ok, Sock} ->
            Pid = spawn(fun() ->
                receive go -> handle_proxy_conn(Sock, Handler) end
            end),
            ok = gen_tcp:controlling_process(Sock, Pid),
            Pid ! go,
            proxy_loop(LSock, Handler);
        _ -> ok
    end.

handle_proxy_conn(Sock, Handler) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, {http_request, M, {scheme, HostBin, PortBin}, _}}
          when M =:= 'CONNECT'; M =:= <<"CONNECT">> ->
            Host = unicode:characters_to_list(HostBin),
            Port = list_to_integer(unicode:characters_to_list(PortBin)),
            Headers = collect_headers(Sock, []),
            handle_decision(Sock, Handler(Host, Port), Headers);
        _ ->
            gen_tcp:close(Sock)
    end.

collect_headers(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, http_eoh} -> lists:reverse(Acc);
        {ok, {http_header, _, Name, _, Value}} -> collect_headers(Sock, [{Name, Value} | Acc]);
        _ -> lists:reverse(Acc)
    end.

handle_decision(Sock, {forward, BHost, BPort}, _Headers) ->
    forward(Sock, BHost, BPort);
handle_decision(Sock, {forward_if_auth, Expected, BHost, BPort}, Headers) ->
    case lists:keyfind('Proxy-Authorization', 1, Headers) of
        {_, Expected} -> forward(Sock, BHost, BPort);
        _ -> reject(Sock)
    end;
handle_decision(Sock, reject, _Headers) ->
    reject(Sock).

reject(Sock) ->
    ok = inet:setopts(Sock, [{packet, raw}]),
    gen_tcp:send(Sock, <<"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n">>),
    gen_tcp:close(Sock).

forward(Sock, BHost, BPort) ->
    ok = inet:setopts(Sock, [{packet, raw}]),
    case gen_tcp:connect(BHost, BPort, [binary, {active, false}, {packet, raw}], 3000) of
        {ok, Backend} ->
            gen_tcp:send(Sock, <<"HTTP/1.1 200 Connection established\r\n\r\n">>),
            relay(Sock, Backend);
        _ ->
            gen_tcp:send(Sock, <<"HTTP/1.1 502 Bad Gateway\r\n\r\n">>),
            gen_tcp:close(Sock)
    end.

relay(A, B) ->
    inet:setopts(A, [{active, true}]),
    inet:setopts(B, [{active, true}]),
    relay_loop(A, B).

relay_loop(A, B) ->
    receive
        {tcp, A, Data} -> gen_tcp:send(B, Data), relay_loop(A, B);
        {tcp, B, Data} -> gen_tcp:send(A, Data), relay_loop(A, B);
        {tcp_closed, _} -> gen_tcp:close(A), gen_tcp:close(B);
        _ -> relay_loop(A, B)
    end.

t_ssl_sock(Config) ->
    SslOpts = [{certfile, certfile(Config)},
               {keyfile, keyfile(Config)},
               {verify, verify_none}
              ],
    {Server, _} = ssl_server:start_link(4443, SslOpts),
    {ok, Sock} = emqtt_sock:connect("127.0.0.1", 4443, [{ssl_opts, [{verify, verify_none}]}], 3000),
    send_and_recv_with(Sock),
    ok = emqtt_sock:close(Sock),
    ssl_server:stop(Server).

gen_connect_test(Config) ->
    {Server, LSock} = ssl_server:start_link(0, ?config(server_ssl_opts, Config)),
    {ok, {_, SPort}} = ssl:sockname(LSock),
    ConnRes = emqtt_sock:connect(?config(target_host, Config), SPort,
                             [{ssl_opts, ?config(client_ssl_opts, Config)}], 3000),
    case ?config(expect_pass, Config) of
        true ->
            {ok, Sock} = ConnRes,
            send_and_recv_with(Sock);
        false ->
            case ConnRes of
                {ok, Sock} ->
                    %% connect success but get disconnect later
                    ?assertException(error, {badmatch, _}, send_and_recv_with(Sock));
                _ ->
                    ?assertMatch({error,
                                  {tls_alert,
                                   {unknown_ca,
                                    _}}}, ConnRes)
            end
    end,
    ssl_server:stop(Server).

send_and_recv_with(Sock) ->
    {ok, [{send_cnt, SendCnt}, {recv_cnt, RecvCnt}]} = emqtt_sock:getstat(Sock, [send_cnt, recv_cnt]),
    {ok, {{127,0,0,1}, _}} = emqtt_sock:sockname(Sock),
    ok = emqtt_sock:send(Sock, <<"hi">>),
    {ok, <<"hi">>} = emqtt_sock:recv(Sock, 0),
    ok = emqtt_sock:setopts(Sock, [{active, 100}]),
    {ok, Stats} = emqtt_sock:getstat(Sock, [send_cnt, recv_cnt]),
    Stats = [{send_cnt, SendCnt + 1}, {recv_cnt, RecvCnt + 1}].

tlsv13_connect_test(Config) ->
    ServerSslOpts = ?config(server_ssl_opts, Config),
    ClientSslOpts = ?config(client_ssl_opts, Config),
    Port = 1024 + random:uniform(erlang:system_info(port_limit) - 1024),
    {Server, _} = ssl_server:start_link(Port, ServerSslOpts),
    {ok, Sock} = emqtt_sock:connect(?config(target_host, Config), Port, [{ssl_opts, ClientSslOpts}], 3000),
    send_and_recv_with(Sock),
    ok = emqtt_sock:close(Sock),
    ssl_server:stop(Server).

%%--------------------------------------------------------------------
%% Helper functions
%%--------------------------------------------------------------------
certfile(Config) ->
    filename:join([cert_dir(Config), "localhost.pem"]).

keyfile(Config) ->
    filename:join([cert_dir(Config), "localhost.key"]).

cert_dir(Config) ->
    filename:join([test_dir(Config), "certs"]).
test_dir(Config) ->
    filename:dirname(filename:dirname(proplists:get_value(data_dir, Config))).

