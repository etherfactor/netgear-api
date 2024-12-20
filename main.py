import hashlib
import html
import logging
import os
import re
from typing import Any, Callable, Optional, TypedDict
from urllib.parse import urlparse

import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import Response
from fastapi.security import APIKeyHeader
from requests import Response, Session
from requests.auth import HTTPBasicAuth

load_dotenv()

app = FastAPI()

#Extract environment variables
PORT = int(os.getenv("NETGEAR_API_PORT"))
API_KEY = os.getenv("NETGEAR_API_APIKEY")

ROUTER_USERNAME = os.getenv("NETGEAR_API_ROUTER_USERNAME")
ROUTER_PASSWORD = os.getenv("NETGEAR_API_ROUTER_PASSWORD")

ROUTER_URL = os.getenv("NETGEAR_API_ROUTER_URL")

#Configure logging
logging.basicConfig()
logging.getLogger().setLevel(logging.INFO)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

class PortForward(TypedDict):
    """Data representing an individual port-forward."""
    id: str
    name: str
    ip: str
    externalPorts: list[str]
    internalPorts: list[str]
    index: int

class RouterManager:
    """Provides methods for managing port-forwards."""
    def __init__(self, base_url, username, password, max_attempts=2):
        parsed = urlparse(base_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.session = Session()
        self.session.auth = HTTPBasicAuth(username=username, password=password)
        self.max_attempts = max_attempts
        self.session_id: str | None = None

    def __authenticate(self) -> None:
        """Authenticates the session. This seems to work by performing a GET with Basic auth several times."""
        response = self.session.get(self.base_url)
        if response.status_code == 401:
            response = self.session.get(self.base_url)

        if not response.ok:
            raise Exception(f"Authentication failed with status code {response.status_code}")
        
    def __retry(self, max_tries, callback):
        """Executes a function up to a certain number of times. Re-authenticates between attempts."""
        attempt = 0
        result = None
        while attempt < max_tries:
            try:
                result = callback()
            except Exception as ex:
                self.__authenticate()
                if attempt >= max_tries:
                    raise
            finally:
                attempt = attempt + 1

        return result

    def __fetch_id(self) -> str:
        """Fetches and extracts the current session id."""
        def exec_request():
            url = f"{self.base_url}/FW_forward3.htm"
            response = self.session.get(url)
            if not response.ok:
                raise Exception(f"Request failed with status code {response.status_code}")
            return response
        
        #The session id comes from a form tag
        response = self.__retry(self.max_attempts, exec_request)
        regex = rf"pforward\.cgi\?id=([0-9a-f]+)"
        match = re.search(regex, response.text)

        if match:
            self.session_id = match.group(1)
        else:
            raise Exception(f"Failed to extract id from FW_forward3.htm")
        
        return self.session_id
    
    def __std_get(self, url: Callable[[], str]) -> Response:
        """Performs a standard GET request against the router's web interface."""
        def exec_request():
            response = self.session.get(url())
            if not response.ok:
                raise Exception(f"Request failed with status code {response.status_code}")
            return response
        
        response = self.__retry(self.max_attempts, exec_request)
        return response
    
    def __ssn_post(self, url: Callable[[], str], data: dict[str, Any]) -> Response:
        """Performs a session POST request against the router's web interface."""
        regex = rf"your timestamp is expired"
        def exec_request():
            response = self.session.post(url(), data=data)
            if not response.ok:
                raise Exception(f"Request failed with status code {response.status_code}")
            #If the response contains the regex text, the session id is expired
            match = re.search(regex, response.text)
            if match:
                self.__fetch_id()
                raise Exception("Router response indicated expired session")
            return response

        response = self.__retry(self.max_attempts, exec_request)
        return response
    
    def get_forwards(self) -> list[PortForward]:
        """Gets a list of port-forwards from the router."""
        url = lambda: f"{self.base_url}/FW_forward3.htm"
        response = self.__std_get(url)

        #Read table spans to extract port-forward data
        regex = re.compile(
            rf"<input type=RADIO name=RouteSelect value=(?P<ID>\d+)>.*?"
            rf"<span class=ttext>(?P<NAME>[^<]+)<\/span>.*?"
            rf"<span class=ttext>(?P<EPORT>[^<]+)<\/span>.*?"
            rf"<span class=ttext>(?P<IPORT>[^<]+)<\/span>.*?"
            rf"<span class=ttext>(?P<IP>[^<]+)<\/span>",
            re.DOTALL
        )

        #Find all matches and map to objects
        matches = re.finditer(regex, response.text)

        routes: list[PortForward] = [
            {
                "id": hashlib.sha256(html.unescape(match.group("NAME")).encode("utf-8")).hexdigest()[:8],
                "name": html.unescape(match.group("NAME")),
                "ip": match.group("IP"),
                "externalPorts": match.group("EPORT").split(','),
                "internalPorts": match.group("IPORT").split(','),
                "index": int(match.group("ID")),
            }
            for match in matches
        ]

        return routes
    
    def create_forward(self, data: PortForward) -> PortForward:
        """Creates a new port-forward."""
        input_regex = re.compile(rf'<input type="hidden" name="(?P<NAME>[^"]*)"(?: value="(?P<VAL>[^"]*))?')

        #Extract the input parameters from the port-forward list page
        list_url = lambda: f"{self.base_url}/FW_forward3.htm"
        response = self.__std_get(list_url)
        matches = re.finditer(input_regex, response.text)
        
        #Create request payload
        view_data = {
            "Add": "Add Custom Service",
            "serv_type": "pf",
            "action": "custom",
            "selectEntry": "",
        }

        for match in matches:
            name = match.group("NAME") or ""
            value = match.group("VAL") or ""
            if view_data.get(name) == None:
                view_data[name] = value

        #Extract the input parameters from the port-forward detail page
        view_url = lambda: f"{self.base_url}/pforward.cgi?id={self.session_id}"
        response = self.__ssn_post(view_url, view_data)
        matches = re.finditer(input_regex, response.text)

        #Create request payload
        create_data = {
            "apply": "Apply",
            "portname": data["name"],
            "srvtype": "TCP/UDP",
            "port_start": ",".join(data["externalPorts"]),
            "internal_port_start": ",".join(data["internalPorts"]),
            "server_ip1": data["ip"].split('.')[0],
            "server_ip2": data["ip"].split('.')[1],
            "server_ip3": data["ip"].split('.')[2],
            "server_ip4": data["ip"].split('.')[3],
            "action": "add_apply",
            "newType": "TCP/UDP",
            "newIP": data["ip"],
            "entryData": "",
        }

        for match in matches:
            name = match.group("NAME") or ""
            value = match.group("VAL") or ""
            if create_data.get(name) == None:
                create_data[name] = value

        #Perform the creation
        create_url = lambda: f"{self.base_url}/pforward.cgi?id={self.session_id}"
        response = self.__ssn_post(create_url, create_data)

        #Find the created entry
        forwards = self.get_forwards()
        forwards.reverse()
        forward = next((x for x in forwards if x["name"] == create_data["portname"]), None)

        return forward

    def update_forward(self, id: str, data: PortForward) -> PortForward:
        """Updates an existing port-forward."""
        input_regex = re.compile(rf'<input type="hidden" name="(?P<NAME>[^"]*)"(?: value="(?P<VAL>[^"]*))?')

        #Extract the input parameters from the port-forward list page
        list_url = lambda: f"{self.base_url}/FW_forward3.htm"
        response = self.__std_get(list_url)
        matches = re.finditer(input_regex, response.text)
        
        #Find the specified port-forward entry
        forwards = self.get_forwards()
        forwards.reverse()
        forward = next((x for x in forwards if x["id"] == id), None)
        if forward == None:
            raise HTTPException(status_code=404)

        #Create request payload
        view_data = {
            "Edit": "Edit Service",
            "serv_type": "pf",
            "RouteSelect": forward["index"],
            "action": "edit",
            "selectEntry": forward["index"],
        }

        for match in matches:
            name = match.group("NAME") or ""
            value = match.group("VAL") or ""
            if view_data.get(name) == None:
                view_data[name] = value

        #Extract the input parameters from the port-forward detail page
        view_url = lambda: f"{self.base_url}/pforward.cgi?id={self.session_id}"
        response = self.__ssn_post(view_url, view_data)
        matches = re.finditer(input_regex, response.text)

        #Create request payload
        update_data = {
            "apply": "Apply",
            "portname": data.get("name") or forward["name"],
            "srvtype": "TCP/UDP",
            "port_start": ",".join(data.get("externalPorts") or forward["externalPorts"]),
            "internal_port_start": ",".join(data.get("internalPorts") or forward["internalPorts"]),
            "server_ip1": data.get("ip").split('.')[0] or forward["ip"].split('.')[0],
            "server_ip2": data.get("ip").split('.')[1] or forward["ip"].split('.')[1],
            "server_ip3": data.get("ip").split('.')[2] or forward["ip"].split('.')[2],
            "server_ip4": data.get("ip").split('.')[3] or forward["ip"].split('.')[3],
            "action": "edit_apply",
            "newType": "TCP/UDP",
            "newIP": data.get("ip") or forward["ip"],
            "entryData": "NoEdit",
        }

        for match in matches:
            name = match.group("NAME") or ""
            value = match.group("VAL") or ""
            if update_data.get(name) == None:
                update_data[name] = value

        #Perform the update
        update_url = lambda: f"{self.base_url}/pforward.cgi?id={self.session_id}"
        response = self.__ssn_post(update_url, update_data)

        #Find the updated entry
        forwards = self.get_forwards()
        forwards.reverse()
        forward = next((x for x in forwards if x["name"] == update_data["portname"]), None)

        return forward
    
    def delete_forward(self, id: str) -> PortForward:
        """Deletes an existing port-forward."""
        input_regex = re.compile(rf'<input type="hidden" name="(?P<NAME>[^"]*)"(?: value="(?P<VAL>[^"]*))?')

        #Extract the input parameters from the port-forward list page
        list_url = lambda: f"{self.base_url}/FW_forward3.htm"
        response = self.__std_get(list_url)
        matches = re.finditer(input_regex, response.text)
        
        #Find the specified port-forward entry
        forwards = self.get_forwards()
        forwards.reverse()
        forward = next((x for x in forwards if x["id"] == id), None)
        if forward == None:
            raise HTTPException(status_code=404)

        #Create request payload
        view_data = {
            "Delete": "Delete Service",
            "serv_type": "pf",
            "RouteSelect": forward["index"],
            "action": "delete",
            "selectEntry": forward["index"],
        }

        for match in matches:
            name = match.group("NAME") or ""
            value = match.group("VAL") or ""
            if view_data.get(name) == None:
                view_data[name] = value

        #Perform the deletion
        delete_url = lambda: f"{self.base_url}/pforward.cgi?id={self.session_id}"
        response = self.__ssn_post(delete_url, view_data)
        if not response.ok:
            raise Exception(f"Failed to delete forward {id}")

manager = RouterManager(base_url=ROUTER_URL, username=ROUTER_USERNAME, password=ROUTER_PASSWORD)

header_scheme = APIKeyHeader(name="api-key")

def validate_apikey(api_key: Optional[str] = Header(None)) -> str:
    if api_key != API_KEY:
        raise HTTPException(status_code=401)
    return api_key

@app.get("/ports")
async def get_ports(key: str = Depends(validate_apikey)):
    forwards = manager.get_forwards()
    forwards.sort(key=lambda x: x["name"])
    return forwards

@app.post("/ports")
async def create_port(request: Request, key: str = Depends(validate_apikey)):
    return manager.create_forward(await request.json())

@app.patch("/ports/{id}")
async def update_port(id: str, request: Request, key: str = Depends(validate_apikey)):
    return manager.update_forward(id, await request.json())

@app.delete("/ports/{id}")
async def delete_port(id: str, key: str = Depends(validate_apikey)):
    manager.delete_forward(id)
    return Response(status_code=204)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, timeout_keep_alive=120)
