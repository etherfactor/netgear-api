# Netgear Port Forwarding API
This Python application provides a RESTful API for managing port forwarding rules on Netgear routers that support the https://routerlogin.net interface. It utilizes FastAPI for the web server and includes functionality to authenticate with the router, retrieve existing port forwarding rules, and add, update, or delete them.

## Features
-  **Retrieve Port Forwarding Rules**: Fetch a list of current port forwarding rules.
-  **Add Rules**: Create new port forwarding rules on the router.
-  **Update Rules**: Modify existing port forwarding rules.
-  **Delete Rules**: Remove port forwarding rules.
-  **Authentication**: API is secured using an API key.

## Requirements
- Python 3.10 or later
- A Netgear router that supports the required API endpoints

## Setup
1. Clone the repository:
    ```bash
    git clone <repository-url>
	cd <repository-folder>
	```
2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3. Set up environment variables: Create a `.env` file in the root directory with the following keys:
    ```
    NETGEAR_API_PORT=8000
    NETGEAR_API_APIKEY=your_api_key
    NETGEAR_API_ROUTER_USERNAME=your_router_username
    NETGEAR_API_ROUTER_PASSWORD=your_router_password
    NETGEAR_API_ROUTER_URL=http://your.router.ip.address
    ```
4. Run the server:
    - Development
        ```bash
        python main.py
        ```
    - Production
        ```bash
        uvicorn main:app --host 0.0.0.0 --port 8000
        ```

## Endpoints

### Get Port Forwards
**GET** `/ports`
Retrieve the list of current port forwarding rules.

- **Headers**:
    - `api-key`: The API key for authentication.
- **Response**:
    - 200 OK
        - A JSON array of port forwarding rules.
        - ```json
          [
            {
              "id": "1a2b3c4d",
              "name": "Rule Name",
              "ip": "192.168.1.100",
              "externalPorts": ["8080"],
              "internalPorts": ["80"],
              "index": 1
            }
	      ]
          ```
    - 401 Unauthorized

---

### Create Port Forward
**POST** `/ports`
Create a new port forwarding rule.

- **Headers**:
    - `api-key`: The API key for authentication.
- **Body**:
    - A JSON object of the new port forwarding rule.
    - ```json
      {
        "name": "Rule Name",
        "ip": "192.168.1.100",
        "externalPorts": ["8080"],
        "internalPorts": ["80"]
      }
      ```
- **Response**:
    - 200 OK
        - A JSON object of the new port forwarding rule.
        - ```json
          {
            "id": "1a2b3c4d",
            "name": "Rule Name",
            "ip": "192.168.1.100",
            "externalPorts": ["8080"],
            "internalPorts": ["80"],
            "index": 1
          }
          ```
    - 401 Unauthorized

---

### Update Port Forward
**PATCH** `/ports/{id}`
Update an existing port forwarding rule.

- **Headers**:
    -   `api-key`: The API key for authentication.
- **Parameters**:
    - `id`: The unique ID of the port forwarding rule.
- **Body**:
    - A JSON object of the updated port forwarding rule.
    - ```json
      {
        "ip": "192.168.1.100"
      }
      ```
- **Response**:
    - 200 OK
        - A JSON object of the updated port forwarding rule.
        - ```json
          {
            "id": "1a2b3c4d",
            "name": "Rule Name",
            "ip": "192.168.1.100",
            "externalPorts": ["8080"],
            "internalPorts": ["80"],
            "index": 1
          }
          ```
    - 401 Unauthorized
    - 404 Not Found

---

### Delete Port Forward
**DELETE** `/ports/{id}`
Delete an existing port forwarding rule.

- **Headers**:
    -   `api-key`: The API key for authentication.
- **Parameters**:
    - `id`: The unique ID of the port forwarding rule.
- **Response**:
    - 204 No Content
    - 401 Unauthorized
    - 404 Not Found

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Feel free to submit issues and pull requests. Contributions are welcome!
