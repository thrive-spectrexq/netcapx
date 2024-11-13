# netcapx

netcapx is a network capturing tool that provides a GUI for capturing network packets.

## Backend Setup

1. **Navigate to the backend folder**:

   ```bash
   cd backend/app

2. Create a virtual environment (optional but recommended):

   ```bash
   python -m venv venv
   source venv/bin/activate  # On macOS/Linux
   venv\Scripts\activate  # On Windows
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the backend server:

   ```bash
   cd ..
   uvicorn app.main:app --reload
   ```

- The backend will be accessible at <http://localhost:8000>

## Frontend Setup

1. **Navigate to the frontend folder**:

   ```bash
   cd frontend
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Start the Electron app:

   ```bash
   npm run start
   ```

- This will build the frontend and launch the Electron app

## LICENSE

- This project is licensed under the [MIT License](LICENSE).
