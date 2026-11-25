"""One-time bootstrap for the local vulnerable WordPress lab.

Installs WordPress and creates an Author-level account through the real
admin UI. Everything here is real HTTP against the docker-compose target;
there are no mocks or simulated responses.

Usage:
    docker compose up -d --build
    # wait for the container to become healthy
    python lab_setup.py

Resulting credentials (lab only):
    admin:  labadmin / Lab_Pass_2026!
    author: labauthor / Author_Pass_2026
"""
from __future__ import annotations

import re
from xrpc.core import RPCClient, WPSession

BASE = "http://127.0.0.1:8080/"
ADMIN = "labadmin"
ADMIN_PASS = "Lab_Pass_2026!"
AUTHOR = "labauthor"
AUTHOR_PASS = "Author_Pass_2026"


def main() -> None:
    sess = WPSession(BASE, RPCClient(BASE))
    st, body, _ = sess.request("wp-admin/install.php")
    if "weblog_title" in body:
        print("[*] Installing WordPress...")
        sess.cookies.setdefault("wordpress_test_cookie", "WP+Cookie+check")
        st, body, _ = sess.request("wp-admin/install.php?step=2", method="POST", form={
            "weblog_title": "XRPC Lab", "user_name": ADMIN,
            "admin_password": ADMIN_PASS, "admin_password2": ADMIN_PASS,
            "admin_email": "lab@xrpc.local", "blog_public": "0",
            "submit": "Install WordPress",
        })
        print("[+] Installed" if "Success" in body else "[!] Install status unclear")

    print("[*] Logging in as %s..." % ADMIN)
    if not sess.login(ADMIN, ADMIN_PASS):
        print("[!] Login failed")
        return
    print("[+] Logged in")

    st, body, _ = sess.request("wp-admin/users.php")
    if AUTHOR in body:
        print("[+] Author account already exists")
    else:
        st, body, _ = sess.request("wp-admin/user-new.php")
        hidden = WPSession.hidden_inputs(body)
        nonce = hidden.get("_wpnonce_create-user")
        if not nonce:
            print("[!] Could not get create-user nonce")
            return
        form = dict(hidden)
        form.update({
            "action": "createuser", "user_login": AUTHOR,
            "email": "author@xrpc.local", "pass1": AUTHOR_PASS,
            "pass2": AUTHOR_PASS, "role": "author", "send_email": "0",
            "createusersub": "Add New User",
        })
        sess.request("wp-admin/user-new.php", method="POST", form=form, follow=False)
        st, body, _ = sess.request("wp-admin/users.php")
        print("[+] Author created" if AUTHOR in body else "[!] Author creation unclear")

    # Verify XML-RPC authentication with the Author account.
    client = RPCClient(BASE + "xmlrpc.php")
    try:
        blogs = client.call_value("wp.getUsersBlogs", AUTHOR, AUTHOR_PASS)
        name = blogs[0].get("blogName") if isinstance(blogs, list) and blogs else "?"
        print("[+] XML-RPC auth OK: %s" % name)
    except Exception as exc:
        print("[!] XML-RPC auth failed: %s" % exc)


if __name__ == "__main__":
    main()
