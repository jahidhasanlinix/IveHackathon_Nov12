import streamlit as st
import openai
import speech_recognition as sr
from gtts import gTTS
import os
import tempfile
import requests
from urllib.parse import urlparse
import folium
from streamlit_folium import folium_static
import ipaddress
import re
import socket

# Set up OpenAI client
openai.api_key = "<your_api_key_paste_here>"
openai.api_base = "https://api.x.ai/v1"

def analyze_message(message):
    try:
        completion = openai.ChatCompletion.create(
            model="grok-beta",
            messages=[
                {"role": "system", "content": "You are an AI assistant designed to detect scams and provide risk assessments. Analyze the given message for potential scams, phishing attempts, or suspicious content. Provide a risk score from 0 to 100, where 0 is no risk and 100 is extremely high risk. Also provide a brief explanation and recommendation."},
                {"role": "user", "content": f"Analyze this message for potential scams: {message}"}
            ]
        )
        return completion.choices[0].message['content']
    except Exception as e:
        return f"An error occurred: {str(e)}"

def analyze_url(url):
    try:
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            return "Invalid URL format"

        # Check if the domain is in a list of known phishing domains
        known_phishing_domains = ["example-phishing.com", "fake-bank.com"]  # Add more to this list
        if parsed_url.netloc in known_phishing_domains:
            return "This URL is associated with known phishing attempts"

        # Check for suspicious TLDs
        suspicious_tlds = [".xyz", ".top", ".work", ".date"]  # Add more suspicious TLDs
        if any(parsed_url.netloc.endswith(tld) for tld in suspicious_tlds):
            return "This URL uses a potentially suspicious top-level domain"

        # Check for URL shorteners
        url_shorteners = ["bit.ly", "tinyurl.com", "goo.gl"]  # Add more URL shorteners
        if any(shortener in parsed_url.netloc for shortener in url_shorteners):
            return "This is a shortened URL, which could potentially hide its true destination"

        return "No immediate red flags detected, but always exercise caution when clicking on links"
    except Exception as e:
        return f"An error occurred while analyzing the URL: {str(e)}"

def get_location(input_data):
    try:
        # Check if input is an IP address
        try:
            ip = ipaddress.ip_address(input_data)
            ip_to_check = str(ip)
        except ValueError:
            # If not an IP, assume it's a URL or domain
            parsed_url = urlparse(input_data)
            domain = parsed_url.netloc or parsed_url.path
            try:
                ip_to_check = socket.gethostbyname(domain)
            except socket.gaierror:
                return None, None, None, None

        response = requests.get(f"https://ipapi.co/{ip_to_check}/json/")
        data = response.json()
        return data.get('latitude'), data.get('longitude'), data.get('city'), data.get('country_name')
    except Exception as e:
        st.error(f"Error getting location: {str(e)}")
        return None, None, None, None

def create_map(latitude, longitude, city, country):
    m = folium.Map(location=[latitude, longitude], zoom_start=10)
    folium.Marker(
        [latitude, longitude],
        popup=f"{city}, {country}",
        tooltip="Click for more info"
    ).add_to(m)
    return m

def text_to_speech(text):
    tts = gTTS(text=text, lang='en')
    with tempfile.NamedTemporaryFile(delete=False, suffix='.mp3') as fp:
        tts.save(fp.name)
        return fp.name

def speech_to_text():
    try:
        r = sr.Recognizer()
        with sr.Microphone() as source:
            st.write("Listening... Speak now.")
            audio = r.listen(source)
            st.write("Processing speech...")
        try:
            text = r.recognize_google(audio)
            return text
        except sr.UnknownValueError:
            return "Sorry, I couldn't understand the audio."
        except sr.RequestError:
            return "Sorry, there was an error processing your speech."
    except OSError:
        st.error("No microphone detected. Please check your microphone connection and system settings.")
        return None

def extract_urls_and_ips(text):
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\$$\$$,]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    urls = url_pattern.findall(text)
    ips = ip_pattern.findall(text)
    
    return urls, ips

def main():
    st.title("ScamGuard: Your Advanced Financial Safety Companion")
    
    input_method = st.radio("Choose input method:", ("Text", "Voice", "URL"))
    
    if input_method == "Text":
        user_input = st.text_area("Paste suspicious message here:")
    elif input_method == "Voice":
        if st.button("Start Voice Input"):
            user_input = speech_to_text()
            if user_input:
                st.write(f"You said: {user_input}")
            else:
                st.warning("Voice input is not available. Please try another input method.")
                return
    else:
        user_input = st.text_input("Enter a URL to analyze:")
    
    if st.button("Analyze Input"):
        if user_input:
            with st.spinner("Analyzing input..."):
                urls, ips = extract_urls_and_ips(user_input)
                
                if input_method == "URL" or urls:
                    for url in (urls or [user_input]):
                        st.subheader(f"URL Analysis for: {url}")
                        url_analysis = analyze_url(url)
                        st.write(url_analysis)
                        
                        lat, lon, city, country = get_location(url)
                        if lat and lon:
                            st.write(f"Location: {city}, {country}")
                            map = create_map(lat, lon, city, country)
                            folium_static(map)
                        else:
                            st.write("Could not determine the location for this URL.")
                
                if ips:
                    for ip in ips:
                        st.subheader(f"IP Analysis for: {ip}")
                        lat, lon, city, country = get_location(ip)
                        if lat and lon:
                            st.write(f"Location: {city}, {country}")
                            map = create_map(lat, lon, city, country)
                            folium_static(map)
                        else:
                            st.write("Could not determine the location for this IP address.")
                
                st.subheader("Message Content Analysis:")
                content_analysis = analyze_message(user_input)
                st.write(content_analysis)
                
                # Text-to-speech output
                audio_file = text_to_speech(content_analysis)
                st.audio(audio_file)
                os.unlink(audio_file)  # Delete the temporary audio file
        else:
            st.warning("Please enter a message, speak, or provide a URL to analyze.")

if __name__ == "__main__":
    main()
