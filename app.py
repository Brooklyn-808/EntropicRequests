import streamlit as st
import json
import hashlib
import uuid
import datetime

USERS_FILE = 'users.json'
REQUESTS_FILE = 'requests.json'
MONTHLY_REQUEST_LIMIT = 2

def load_data(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        st.warning(f"File '{filename}' not found or corrupted. Initializing as empty.")
        if filename == USERS_FILE:
            return {}
        elif filename == REQUESTS_FILE:
            return {}
        else:
            return {}

def save_data(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, provided_password):
    return stored_hash == hash_password(provided_password)

def main():
    st.title("Entropic Requests")

    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'username' not in st.session_state:
        st.session_state.username = None

    users = load_data(USERS_FILE)
    requests_data = load_data(REQUESTS_FILE)

    if not st.session_state.logged_in:
        st.sidebar.header("Account Management")
        selected_option = st.sidebar.radio("Choose an option", ["Login", "Create Account"])

        if selected_option == "Create Account":
            st.subheader("Create New Account")
            new_username = st.text_input("New Username")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")

            if st.button("Create Account"):
                if new_username and new_password and confirm_password:
                    if new_password == confirm_password:
                        if new_username not in users:
                            users[new_username] = {
                                "password": hash_password(new_password),
                                "requests_left": MONTHLY_REQUEST_LIMIT,
                                "last_request_reset": None
                            }
                            save_data(users, USERS_FILE)
                            st.success("Account created successfully! Please log in.")
                        else:
                            st.error("Username already exists. Please choose a different one.")
                    else:
                        st.error("Passwords do not match.")
                else:
                    st.warning("Please fill in all fields.")

        elif selected_option == "Login":
            st.subheader("Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")

            if st.button("Login"):
                if username in users:
                    if verify_password(users[username]["password"], password):
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.success(f"Welcome, {username}!")
                        st.rerun()
                    else:
                        st.error("Incorrect password.")
                else:
                    st.error("Username not found.")
    else:
        st.sidebar.write(f"Logged in as: **{st.session_state.username}**")
        if st.sidebar.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.username = None
            st.rerun()

        st.header(f"Welcome, {st.session_state.username}!")

        current_user_data = users.get(st.session_state.username, {})
        requests_left = current_user_data.get("requests_left", 0)
        st.info(f"You have **{requests_left}** requests remaining this month.")

        st.subheader("Submit a Request")
        user_request_text = st.text_area("Your Request (max 200 characters)", max_chars=200)

        if st.button("Submit Request"):
            if requests_left > 0:
                if user_request_text:
                    request_id = str(uuid.uuid4())
                    requests_data[request_id] = {
                        "id": request_id,
                        "username": st.session_state.username,
                        "request_text": user_request_text,
                        "timestamp": datetime.datetime.now().isoformat()
                    }
                    save_data(requests_data, REQUESTS_FILE)

                    users[st.session_state.username]["requests_left"] -= 1
                    save_data(users, USERS_FILE)

                    st.success("Your request has been submitted!")
                    st.rerun()
                else:
                    st.warning("Please enter your request.")
            else:
                st.error("You have no requests left this month. Please wait for your requests to be refilled.")

        # Conditional display for "Entropy" user
        if st.session_state.username == "Entropy":
            st.subheader("All Past Requests (Admin View)")
            displayed_requests = list(requests_data.values())
        else:
            st.subheader("Your Past Requests")
            displayed_requests = [
                req for req in requests_data.values() if req["username"] == st.session_state.username
            ]

        if displayed_requests:
            displayed_requests.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            for req in displayed_requests:
                st.write(f"**Request ID:** {req['id']}")
                # Only show username if it's the admin view
                if st.session_state.username == "Entropy":
                    st.write(f"**User:** {req['username']}")
                st.write(f"**Submitted:** {req['timestamp']}")
                st.write(f"**Content:** {req['request_text']}")
                st.markdown("---")
        else:
            if st.session_state.username == "Entropy":
                st.info("No requests have been submitted by any user yet.")
            else:
                st.info("You haven't submitted any requests yet.")

if __name__ == "__main__":
    main()
