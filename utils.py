import threading

def run_in_thread(target, args=None):
    if args is None:
        args = []
    thread = threading.Thread(target=target, args=args)
    thread.daemon = True  # Set the thread as a daemon, so it exits when the main program ends
    thread.start()
