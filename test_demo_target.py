from demo_target import REVIEWS, SESSIONS, USERS, start_demo_server


def test_demo_server_resets_shared_state():
    server, _ = start_demo_server()
    try:
        USERS["phobos-test"]["deleted"] = True
        REVIEWS.append(("demo", "seeded"))
        SESSIONS["token"] = "phobos-test"
    finally:
        server.server_close()

    server2, _ = start_demo_server()
    try:
        assert USERS == {"phobos-test": {"password": "phobos-test", "deleted": False}}
        assert REVIEWS == []
        assert SESSIONS == {}
    finally:
        server2.server_close()
