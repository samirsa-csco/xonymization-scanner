"""Splunk client for connecting and querying Splunk."""

import json
from typing import Any, Dict, List, Optional
from datetime import datetime
import requests
from requests.auth import HTTPBasicAuth
import urllib3


class SplunkClient:
    """Client for interacting with Splunk REST API."""

    def __init__(
        self,
        host: str,
        port: int = 8089,
        username: Optional[str] = None,
        password: Optional[str] = None,
        token: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        """
        Initialize Splunk client.

        Args:
            host: Splunk server hostname or IP
            port: Splunk management port (default: 8089)
            username: Username for authentication
            password: Password for authentication
            token: Bearer token for authentication (alternative to username/password)
            verify_ssl: Whether to verify SSL certificates
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.token = token
        self.verify_ssl = verify_ssl
        # Use HTTPS with management port for Splunk Cloud API
        self.base_url = f"https://{host}:{port}"
        self.session = requests.Session()
        
        # Disable SSL warnings if SSL verification is disabled
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        if token:
            self.session.headers.update({"Authorization": f"Bearer {token}"})
        elif username and password:
            self.session.auth = HTTPBasicAuth(username, password)
        else:
            raise ValueError("Either token or username/password must be provided")

    def search(
        self,
        query: str,
        index: Optional[str] = None,
        earliest_time: Optional[str] = "-15m",
        latest_time: Optional[str] = "now",
        max_results: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Execute a search query on Splunk.

        Args:
            query: SPL (Search Processing Language) query
            index: Splunk index to search (optional, can be in query)
            earliest_time: Earliest time for search (default: -15m)
            latest_time: Latest time for search (default: now)
            max_results: Maximum number of results to return

        Returns:
            List of log events as dictionaries
        """
        # Build the full search query
        search_query = query
        if index and "index=" not in query:
            search_query = f"search index={index} {query}"
        elif "search" not in query.lower():
            search_query = f"search {query}"

        # Create search job against Splunk management API
        search_url = f"{self.base_url}/services/search/jobs"
        search_params = {
            "search": search_query,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "output_mode": "json",
        }

        try:
            response = self.session.post(
                search_url,
                data=search_params,
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            
            # Get the search job ID
            job_data = response.json()
            sid = job_data.get("sid")
            
            if not sid:
                raise ValueError("Failed to create search job")

            # Wait for search to complete and get results
            return self._get_search_results(sid, max_results)

        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to execute Splunk search: {e}")

    def _get_search_results(self, sid: str, max_results: int) -> List[Dict[str, Any]]:
        """
        Poll for search job completion and retrieve results.

        Args:
            sid: Search job ID
            max_results: Maximum number of results to return

        Returns:
            List of log events
        """
        import time

        job_url = f"{self.base_url}/services/search/jobs/{sid}"
        results_url = f"{job_url}/results"

        # Poll for job completion
        max_wait = 300  # 5 minutes
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            response = self.session.get(
                job_url,
                params={"output_mode": "json"},
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            
            job_status = response.json()
            dispatch_state = job_status.get("entry", [{}])[0].get("content", {}).get("dispatchState")
            
            if dispatch_state == "DONE":
                break
            elif dispatch_state == "FAILED":
                raise RuntimeError("Search job failed")
            
            time.sleep(1)
        else:
            raise TimeoutError("Search job timed out")

        # Get results
        response = self.session.get(
            results_url,
            params={"output_mode": "json", "count": max_results},
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        
        results_data = response.json()
        results = results_data.get("results", [])
        
        return results

    def get_indexes(self) -> List[str]:
        """
        Get list of available Splunk indexes.

        Returns:
            List of index names
        """
        url = f"{self.base_url}/services/data/indexes"
        
        try:
            response = self.session.get(
                url,
                params={"output_mode": "json"},
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            
            data = response.json()
            indexes = [
                entry.get("name")
                for entry in data.get("entry", [])
                if entry.get("name")
            ]
            
            return indexes

        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to get indexes: {e}")

    def test_connection(self) -> bool:
        """
        Test connection to Splunk server.

        Returns:
            True if connection is successful
        """
        url = f"{self.base_url}/services/server/info"
        
        try:
            response = self.session.get(
                url,
                params={"output_mode": "json"},
                verify=self.verify_ssl,
                timeout=10,
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            import sys
            print(f"Connection test failed: {e}", file=sys.stderr)
            print(f"URL attempted: {url}", file=sys.stderr)
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response status: {e.response.status_code}", file=sys.stderr)
                print(f"Response body: {e.response.text[:500]}", file=sys.stderr)
            return False
