import streamlit as st
import requests
import pandas as pd
import numpy as np
from urllib.parse import urlencode, urlparse, parse_qs
from datetime import datetime


#streamlit run app.py --server.address localhost --server.port 8501
#https://www.strava.com/oauth/authorize?client_id=193409&response_type=code&redirect_uri=http://localhost:8501&scope=read&state=mystate 
#http://localhost:8501/?state=mystate&code=468da511f9df64134137c18c05892904a29f6d66&scope=read

# Replace these with your own values
CLIENT_ID = '193409'
CLIENT_SECRET = '750613ca746e6696293be34be9204b68b8a125c3'
#AUTHORIZATION_CODE = '468da511f9df64134137c18c05892904a29f6d66'  # From the URL
REDIRECT_URI = 'http://hutchings.streamlit.app//?page=redirect'  # Redirect URI to capture the cod                # Define the users (replace with actual Strava user IDs)
CLUB_ID = 1895283                      

users = {
    'Meg': 26785678,  # Replace with real Strava athlete ID
    'Dina':67908097
}

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
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': auth_code,
        'grant_type': 'authorization_code'
    }
    response = requests.post(token_url, params=params)
    if response.status_code == 200:
        check_token_scopes(response.json()['access_token'])
        return response.json()['access_token']
    else:
        return None


def refresh_access_token(refresh_token):
    # Your Strava client credentials
    
    # URL to exchange the refresh token for a new access token
    url = 'https://www.strava.com/oauth/token'
    
    # Payload for the refresh request
    payload = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
    }
    
    # Make the request to refresh the access token
    response = requests.post(url, data=payload)
    
    if response.status_code == 200:
        # Parse the response to get the new access token
        data = response.json()
        new_access_token = data['access_token']
        new_refresh_token = data.get('refresh_token', refresh_token)  # Keep the refresh token if provided
        
        return new_access_token, new_refresh_token
    else:
        print(f"Error refreshing access token: {response.json()}")
        return None, None



def check_token_scopes(ACCESS_TOKEN):
    url = 'https://www.strava.com/api/v3/athlete'
    headers = {'Authorization': f'Bearer {ACCESS_TOKEN}'}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        print(f"Authenticated as: {response.json()['username']}")
        print(f"whole response as: {response.json()}")
    else:
        print(f"Error verifying token: {response.json()}")


# Function to get user activities
def get_user_activities(user_id,ACCESS_TOKEN):
    print("ACCESS_TOKEN",ACCESS_TOKEN)
    print(user_id)

    url = f'https://www.strava.com/api/v3/athletes/{user_id}/stats'
    #url = f'https://www.strava.com/api/v3/athlete'
    headers = {'Authorization': f'Bearer {ACCESS_TOKEN}'}
    
    
    params = {
        'before': int(datetime(datetime.now().year, datetime.now().month, datetime.now().day).timestamp()),  # Activities from this year
        'after': int(datetime(datetime.now().year - 1, 12, 31).timestamp()),  # Activities up to the start of this year
        'per_page': 200  # Get up to 200 activities (you can adjust this as needed)
    }


    #response = requests.get(url, headers=headers, params=params)
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        print('success')
        print(response.json())
        return response.json()
    else:
        st.error(f"Error fetching activities: {response.json()}")
        return []
    

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
    
def get_club_activities(club_id, ACCESS_TOKEN, before=None, after=None, per_page=30):
    url = f'https://www.strava.com/api/v3/clubs/{club_id}/activities'
    headers = {'Authorization': f'Bearer {ACCESS_TOKEN}'}
    
    # Optional parameters: before, after, per_page
    params = {
        'before': before,
        'after': after,
        'per_page': per_page
    }

    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        activities = response.json()
        print(f"Fetched {len(activities)} activities from club {club_id}.")
        return activities
    else:
        print(f"Error fetching activities for club {club_id}: {response.json()}")
        return []




def get_user_followers(ACCESS_TOKEN):
    # Get the authenticated user's id
    url = 'https://www.strava.com/api/v3/athlete'
    headers = {'Authorization': f'Bearer {ACCESS_TOKEN}'}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        user_data = response.json()
        user_id = user_data['id']  # This is the authenticated user's ID
        print(f"Authenticated user ID: {user_id}")
        
        # Now, get the list of followers using the authenticated user's ID
        followers_url = f'https://www.strava.com/api/v3/athletes/{user_id}/followers'
        
        followers_response = requests.get(followers_url, headers=headers)
        
        if followers_response.status_code == 200:
            followers_data = followers_response.json()
            # List of follower user IDs
            follower_ids = [follower['id'] for follower in followers_data]
            print(f"Follower IDs: {follower_ids}")
            return follower_ids
        else:
            print(f"Error fetching followers: {followers_response.json()}")
            return []
    else:
        print(f"Error fetching user data: {response.json()}")
        return []


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
    # Get the current page (login or redirect)
    #page = st.experimental_get_query_params().get("page", ["login"])[0]
    
    if "page" in st.query_params:
        if st.query_params["page"] == "login":
            show_login_page()
        elif st.query_params["page"] == "redirect":
            handle_redirect_page()
    else:
        show_login_page()


# Login Page - Generates the Strava Auth URL
def show_login_page():
    st.title('Login with Strava')

    # Display the authorization button
    auth_url = generate_auth_url()
    st.write("Click the button below to authorize with Strava:")
    st.markdown(f"[Authorize with Strava]({auth_url})")

    st.info("After you authorize, you'll be redirected to this app with the authorization code.")

# Redirect Page - Handles the redirection from Strava
def handle_redirect_page():
    # Extract the authorization code from the query parameters
    print("hello, checking params")
    #query_params = st.experimental_get_query_params()
    print(st.query_params)
    if 'code' in st.query_params:
        auth_code = st.query_params['code']
        st.write(f"Authorization Code: {auth_code}")

        # Exchange the code for an access token
        access_token = get_access_token(auth_code)
        if access_token:
            st.success("Successfully authenticated with Strava!")
            
            # Fetch activities for the club in 2026
            activities = get_club_activities(CLUB_ID, access_token, 2026)
            
            # Calculate total kilometers for each athlete
            leaderboard = {}
            for activity in activities:
                athlete_name = activity['athlete']['username']
                if athlete_name not in leaderboard:
                    leaderboard[athlete_name] = 0
                leaderboard[athlete_name] += activity['distance'] / 1000  # Add kilometers
            
            # Display the leaderboard
            display_leaderboard(leaderboard)
        else:
            st.error("Failed to obtain access token.")
    else:
        st.warning("No authorization code found. Make sure to authorize first.")

# Run the app
if __name__ == "__main__":
    app()













