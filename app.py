import json

import requests
import streamlit as st
from requests.auth import HTTPBasicAuth
from streamlit_local_storage import LocalStorage

# Configuration
st.set_page_config(page_title="Perforce", layout="wide")
localS = LocalStorage()


def load_settings():
    return {
        "url": localS.getItem("p4_url") or "http://localhost:11666",
        "user": localS.getItem("p4_user") or "",
        "ticket": localS.getItem("p4_ticket") or "",
        "verify": localS.getItem("verify_ssl") or False,
    }


def save_settings(url, user, ticket, verify):
    localS.setItem("p4_url", url, key="set_url")
    localS.setItem("p4_user", user, key="set_user")
    localS.setItem("p4_ticket", ticket, key="set_ticket")
    localS.setItem("verify_ssl", verify, key="set_verify")


settings = load_settings()

# Sidebar
st.sidebar.title("Connection Settings")
p4_url = st.sidebar.text_input("P4_REST_URL", value=settings["url"])
p4_user = st.sidebar.text_input("P4_USER", value=settings["user"])
p4_ticket = st.sidebar.text_input(
    "P4_TICKET",
    value=settings["ticket"],
    type="password",
    help="Generate via: p4 login -h restapi -p username",
)
verify_ssl = st.sidebar.checkbox("Verify SSL", value=settings["verify"])

if st.sidebar.button("Save Settings"):
    save_settings(p4_url, p4_user, p4_ticket, verify_ssl)
    st.sidebar.success("Settings saved to Browser Storage!")

# Auth
auth = HTTPBasicAuth(p4_user, p4_ticket) if p4_user and p4_ticket else None

st.title("P4 REST API Explorer")

tab1, tab2, tab3 = st.tabs(["Server Health", "Depot Browser", "File Metadata"])


def safe_request(endpoint, stream=False, params=None):
    try:
        url = f"{p4_url.rstrip('/')}{endpoint}"
        # For depots, we might get JSONL, so using stream=False by default but handling content manually
        headers = {"Accept": "application/jsonl"} if stream else {}
        resp = requests.get(
            url, auth=auth, verify=verify_ssl, timeout=5, headers=headers, params=params
        )
        resp.raise_for_status()

        if stream:
            # Handle JSONL
            return [json.loads(line) for line in resp.text.splitlines() if line.strip()]
        return resp.json()
    except requests.exceptions.SSLError:
        st.error(f"SSL Error: Could not verify certificate for {url}")
    except requests.exceptions.ConnectionError:
        st.error(f"Connection Error: Could not reach {url}")
    except requests.exceptions.JSONDecodeError as e:
        st.error(f"JSON Error: {e} - Response: {resp.text[:100]}...")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            st.error("Authentication Failed: Check your username and ticket.")
        else:
            st.error(f"HTTP Error: {e}")
    except Exception as e:
        st.error(f"Error: {e}")
    return None


with tab1:
    version_data = safe_request("/api/version")
    info_data = safe_request("/api/v0/server/info")

    if version_data and info_data:
        # Format Version: Take "2025.2/2852709" from "P4D/LINUX.../2025.2/2852709"
        raw_ver = version_data.get("version", "N/A")
        ver_parts = raw_ver.split("/")
        display_ver = "/".join(ver_parts[-2:]) if len(ver_parts) >= 2 else raw_ver

        # Format Uptime: PT122H26M12S -> 122h 26m 12s
        raw_uptime = info_data.get("serverUptime", "")
        import re

        uptime_match = re.match(r"PT(\d+)H(\d+)M(\d+)S", raw_uptime)
        if uptime_match:
            h, m, s = uptime_match.groups()
            display_uptime = f"{h}h {m}m {s}s"
        else:
            display_uptime = raw_uptime

        c1, c2, c3 = st.columns(3)
        c1.metric("Version", display_ver, help=raw_ver)
        c2.metric("Uptime", display_uptime)
        c3.metric("ServerID", info_data.get("ServerID", "N/A"))

        c4, c5, c6 = st.columns(3)
        c4.metric("License", info_data.get("serverLicense", "N/A"))
        c5.metric("Case Handling", info_data.get("caseHandling", "N/A"))
        c6.metric("Services", info_data.get("serverServices", "N/A"))

        with st.expander("Raw JSON"):
            st.json({"version": version_data, "info": info_data})

with tab2:
    depots = safe_request("/api/v0/depot", stream=True)
    if depots:
        st.dataframe(depots, width="stretch")
        with st.expander("Raw JSON"):
            st.json(depots)

with tab3:
    st.info("Explore file metadata from the server.")
    file_specs = st.text_input(
        "File Specs", value="//...", help="E.g., //depot/main/..."
    )

    if st.button("Fetch Metadata"):
        if file_specs:
            params = {"max": 20, "fileSpecs": file_specs}
            metadata = safe_request("/api/v0/file/metadata", stream=True, params=params)

            if metadata:
                st.dataframe(metadata, width="stretch")
                with st.expander("Raw JSON"):
                    st.json(metadata)
        else:
            st.warning("Please enter File Specs.")
