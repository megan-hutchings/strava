import streamlit as st
import requests
import pandas as pd
import numpy as np
from urllib.parse import urlencode
from datetime import datetime, timedelta
import json
from streamlit_js_eval import streamlit_js_eval


CLIENT_ID = st.secrets['CLIENT_ID']
CLIENT_SECRET = st.secrets['CLIENT_SECRET']
REDIRECT_URI = 'https://hutchings.streamlit.app/?page=redirect'  # Redirect URI to capture the cod                # Define the users (replace with actual Strava user IDs)                    
TOKENS_FILENAME = "tokens.json"

# handle stored tokens file
def save_tokens(tokens):
    with open(TOKENS_FILENAME, "w") as f:
        json.dump(tokens, f, indent=4)
def load_tokens():
    try:
        with open(TOKENS_FILENAME, "r") as f:
            tokens = json.load(f)
        return tokens
    except FileNotFoundError:
        st.error("no tokens file found")
        return {}
    
# Generate the authorization URL
def generate_auth_url():
    base_url = 'https://www.strava.com/oauth/authorize'
    auth_params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': 'read,activity:read,read_all',
        'state': 'randomstring',  # Optional state to prevent CSRF attacks
    }
    print(base_url + '?' + urlencode(auth_params))
    return base_url + '?' + urlencode(auth_params)

# Exchange the authorization code for an access token
def get_access_token(auth_code):
    token_url = 'https://www.strava.com/oauth/token'
    params = {
        'client_id': st.secrets['CLIENT_ID'],
        'client_secret': st.secrets['CLIENT_SECRET'],
        'code': auth_code,
        'grant_type': 'authorization_code'
    }
    response = requests.post(token_url, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Refresh token
def refresh_access_token(refresh_token):
    url = 'https://www.strava.com/oauth/token'
    payload = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
    }
    response = requests.post(url, data=payload)
    
    if response.status_code == 200:
        data = response.json()
        new_access_token = data['access_token']
        new_refresh_token = data.get('refresh_token', refresh_token)  # Keep the refresh token if provided
        
        return new_access_token, new_refresh_token
    else:
        print(f"Error refreshing access token: {response.json()}")
        return None, None

def get_user_info(client_id,access_token):

    url = "https://www.strava.com/api/v3/athlete"
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        user_data = response.json()

        return user_data  # Return the user_id
    elif response.status_code == 401:  # Token expired
        st.warning("Access token expired. Refreshing...")
        new_access_token, new_refresh_token = refresh_access_token(st.session_state.tokens[client_id]['refresh_token'])
        if new_access_token:
            st.session_state.tokens[client_id]['auth_token'] = new_access_token
            st.session_state.tokens[client_id]['refresh_token'] = new_refresh_token
            save_tokens(st.session_state.tokens)
            return get_user_info(client_id, new_access_token)
        else:
            st.error("Unable to refresh access token.")
            return []
    else:
        st.error(f"Error fetching user data: {response.json()}")
        return None

# Function to get user activities
def get_user_activities(user_id,access_token,selected_year):
    url = f'https://www.strava.com/api/v3/athletes/{user_id}/activities'
    headers = {'Authorization': f'Bearer {access_token}'}
    tomorrow = datetime.now() + timedelta(days=1)
    
    if selected_year == str(datetime.now().year):
        params = {
            'before': int(datetime(tomorrow.year, tomorrow.month, tomorrow.day).timestamp()),  # Activities from this year
            'after': int(datetime(datetime.now().year - 1, 12, 31).timestamp()),  # Activities up to the start of this year
            'per_page': 200, # Get up to 200 activities (you can adjust this as needed)
            'page': 1
        }
    else:
        params = {
            'before': int(datetime(int(selected_year), 12, 31).timestamp()),  # Activities from this year
            'after': int(datetime(int(selected_year)-1, 12, 31).timestamp()),  # Activities up to the start of this year
            'per_page': 200,  # Get up to 200 activities (you can adjust this as needed)
            'page': 1
        }

    all_activities = []
    
    while True:
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            activities = response.json()
            all_activities.extend(activities)
            
            # If there are fewer activities than 'per_page', stop pagination
            if len(activities) < 200:
                break
            else:
                # Otherwise, move to the next page
                params['page'] += 1
        elif response.status_code == 401:  # Token expired
            st.warning("Access token expired. Refreshing...")
            new_access_token, new_refresh_token = refresh_access_token(st.session_state.tokens[user_id]['refresh_token'])
            if new_access_token:
                # Update the access token and refresh token
                st.session_state.tokens[user_id]['auth_token'] = new_access_token
                st.session_state.tokens[user_id]['refresh_token'] = new_refresh_token
                save_tokens(st.session_state.tokens)
                # Retry the request with the new token
                return get_user_activities(user_id, new_access_token)
            else:
                st.error("Unable to refresh access token.")
                return []
        else:
            st.error(f"Error fetching activities: {response.json()}")
            break
    
    return all_activities






    
def get_user_stats(user_id, access_token):
    url = f'https://www.strava.com/api/v3/athletes/{user_id}/stats'
    headers = {'Authorization': f'Bearer {access_token}'}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        stats = response.json()
        return stats
    else:
        print(f"Error fetching stats for user {user_id}: {response.json()}")
        return None
    

def calculate_total_kms(activities):
    total_kms = 0
    for activity in activities:
        if activity['type'] == 'Run':  # Ensure only running activities are counted
            total_kms += activity['distance'] / 1000  # Distance is in meters, convert to kilometers
    return total_kms
# Display leaderboard
def display_leaderboard(leaderboard):
    sorted_leaderboard = sorted(leaderboard.items(), key=lambda x: x[1], reverse=True)
    st.subheader(f"Leaderboard for 2026")
    for rank, (user, total_kms) in enumerate(sorted_leaderboard, start=1):
        st.write(f"{rank}. {user} - {total_kms:.2f} km")


# Main function for the Streamlit app
def app():
    if "page" in st.query_params:
        if st.query_params["page"] == "login":
            show_login_page()
        elif st.query_params["page"] == "redirect":
            handle_redirect_page()
        elif st.query_params["page"] == "leaderboard":
            handle_leaderboard_page()
    else:
        show_login_page()


# Login Page - Generates the Strava Auth URL
def show_login_page():
    st.title('Login with Strava')

    st.session_state["current_user"] = st.secrets["CLIENT_ID"]

    # Load existing tokens
    st.session_state["tokens"] = load_tokens()
    #st.write(st.session_state["tokens"])

    # Check if user is already in the tokens file
    if st.session_state.current_user in st.session_state.tokens:
        st.success(f"User {st.session_state.current_user} is already authenticated!")
        st.query_params["page"] = "leaderboard"
        streamlit_js_eval(js_expressions="parent.window.location.reload()")
    else:
        
        #st.write(f"User {st.session_state.current_user} is not found in tokens.")
        #st.write(f"Adding user {st.session_state.current_user} with token.")
        
        # Display the authorization button
        auth_url = generate_auth_url()
        st.write("Click the button below to authorize with Strava:")
        st.markdown(f"[Authorize with Strava]({auth_url})")

        st.info("After you authorize, you'll be redirected to this app with the authorization code.")




# Redirect Page - Handles the redirection from Strava
def handle_redirect_page():
    st.title('Authorizing...')
    st.session_state["current_user"] = st.secrets["CLIENT_ID"]

    # Load existing tokens
    st.session_state["tokens"] = load_tokens()

    # Extract the authorization code from the query parameters
    if 'code' in st.query_params:
        auth_code = st.query_params['code']
        #st.write(f"Authorization Code: {auth_code}")

        # Exchange the code for an access token
        access_token_data = get_access_token(auth_code)

        if access_token_data: 
            st.success("Successfully authenticated with Strava!")
            #st.write(f"Your access token: {access_token}") 
            user_data = get_user_info(st.session_state.current_user,access_token_data['access_token'])
            user_id =  user_data.get('id') 
            #st.write(f"Your user_id: {user_id}")

            # Add the new token to the dictionary
            #st.session_state.tokens[st.session_state.current_user] = {"auth_token": access_token,"user_id": user_id,"firstname":user_data.get('firstname'),"lastname":user_data.get('lastname')}
            st.session_state.tokens[user_id] = {
                "auth_token": access_token_data['access_token'],
                "refresh_token": access_token_data['refresh_token'],
                "user_id": user_id,
                "firstname": user_data.get('firstname'),
                "lastname": user_data.get('lastname')
            }
            # Save the updated tokens to the file
            save_tokens(st.session_state.tokens)

            st.write("Updated tokens:")
            st.json(st.session_state.tokens)

            st.query_params["page"] = "leaderboard"
            streamlit_js_eval(js_expressions="parent.window.location.reload()")

        else: 
            st.error("Failed to obtain access token.")
    else:
        st.warning("No authorization code found. Make sure to authorize first.")

def handle_leaderboard_page():
    page_options = ["2026", "2025", "2024", "2023"]
    selected_year = st.selectbox("Select a year", page_options)
    st.title(f"Strava Leaderboard - Kilometers Run in {selected_year}")
    leaderboard = {} 

    # Load existing tokens
    st.session_state["tokens"] = load_tokens()
    #st.write(st.session_state.tokens)

    for user, data in st.session_state["tokens"].items():
        user_id = data['user_id']
        access_token = data['auth_token']
        #st.write(data['user_id'])
        #st.write(data['auth_token'])
    
        activities = get_user_activities(user_id, access_token,selected_year) 
        total_kms = calculate_total_kms(activities) 

        leaderboard[f"{data['firstname']} {data['lastname']}"] = total_kms 
        #  Sort leaderboard based on kilometers 
        sorted_leaderboard = sorted(leaderboard.items(), key=lambda x: x[1], reverse=True) 
        # # Display the leaderboard 
        for rank, (user, total_kms) in enumerate(sorted_leaderboard, start=1): 
            st.write(f"{rank}. {user} - {total_kms:.2f} km")
  

# Run the app
if __name__ == "__main__":
    app()


