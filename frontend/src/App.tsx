import axios from "axios";
import { useState } from "react";

function App() {
  const [status, setStatus] = useState("Stopped");

  const startCapture = async () => {
    await axios.get("http://localhost:8000/start_capture");
    setStatus("Capturing");
  };

  const stopCapture = async () => {
    await axios.get("http://localhost:8000/stop_capture");
    setStatus("Stopped");
  };

  return (
    <div>
      <h1>Netcapx - Packet Capture</h1>
      <p>Status: {status}</p>
      <button onClick={startCapture}>Start Capture</button>
      <button onClick={stopCapture}>Stop Capture</button>
    </div>
  );
}

export default App;
