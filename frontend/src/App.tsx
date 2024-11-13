import axios from "axios";
import { CSSProperties, useEffect, useState } from "react";

function App() {
  const [status, setStatus] = useState("Stopped");
  const [summary, setSummary] = useState<string[]>([]);
  const [message, setMessage] = useState("");

  useEffect(() => {
    getStatus();
  }, []);

  const startCapture = async () => {
    try {
      await axios.get("http://localhost:8000/start_capture");
      setStatus("Capturing");
      setMessage("Packet capture started.");
    } catch (error) {
      console.error("Failed to start capture:", error);
    }
  };

  const stopCapture = async () => {
    try {
      await axios.get("http://localhost:8000/stop_capture");
      setStatus("Stopped");
      setMessage("Packet capture stopped.");
    } catch (error) {
      console.error("Failed to stop capture:", error);
    }
  };

  const getStatus = async () => {
    try {
      const response = await axios.get("http://localhost:8000/status");
      setStatus(response.data.status);
    } catch (error) {
      console.error("Failed to fetch status:", error);
    }
  };

  const getSummary = async () => {
    try {
      const response = await axios.get("http://localhost:8000/summary");
      setSummary(response.data.summary);
      setMessage("Capture summary fetched.");
    } catch (error) {
      console.error("Failed to fetch summary:", error);
    }
  };

  const saveCapture = async () => {
    try {
      const response = await axios.post("http://localhost:8000/save_capture", {
        filename: "captured_packets.json",
      });
      setMessage(response.data.status);
    } catch (error) {
      console.error("Failed to save capture:", error);
    }
  };

  const loadCapture = async () => {
    try {
      const response = await axios.post("http://localhost:8000/load_capture", {
        filename: "captured_packets.json",
      });
      setSummary(response.data.packets);
      setMessage("Packets loaded from file.");
    } catch (error) {
      console.error("Failed to load capture:", error);
    }
  };

  const resetCapture = async () => {
    try {
      const response = await axios.post("http://localhost:8000/reset_capture");
      setSummary([]);
      setMessage(response.data.status);
    } catch (error) {
      console.error("Failed to reset capture:", error);
    }
  };

  return (
    <div style={styles.container}>
      <h1 style={styles.header}>Netcapx - Packet Capture</h1>
      <p style={styles.status}>Status: <strong>{status}</strong></p>
      <div style={styles.buttonContainer}>
        <button style={styles.button} onClick={startCapture}>Start Capture</button>
        <button style={styles.button} onClick={stopCapture}>Stop Capture</button>
        <button style={styles.button} onClick={getSummary}>Get Summary</button>
        <button style={styles.button} onClick={saveCapture}>Save Capture</button>
        <button style={styles.button} onClick={loadCapture}>Load Capture</button>
        <button style={styles.button} onClick={resetCapture}>Reset Capture</button>
      </div>

      <div style={styles.messageBox}>
        <h2 style={styles.sectionHeader}>Message</h2>
        <p>{message}</p>
      </div>

      <div style={styles.summaryBox}>
        <h2 style={styles.sectionHeader}>Capture Summary</h2>
        <ul>
          {summary.length > 0 ? (
            summary.map((item, index) => <li key={index}>{item}</li>)
          ) : (
            <p>No packets captured.</p>
          )}
        </ul>
      </div>
    </div>
  );
}

export default App;

// Define the styles with the CSSProperties type
const styles: { 
  container: CSSProperties,
  header: CSSProperties,
  status: CSSProperties,
  buttonContainer: CSSProperties,
  button: CSSProperties,
  messageBox: CSSProperties,
  summaryBox: CSSProperties,
  sectionHeader: CSSProperties
} = {
  container: {
    fontFamily: "Arial, sans-serif",
    maxWidth: "600px",
    margin: "0 auto",
    padding: "20px",
    backgroundColor: "#f0f4f8",
    borderRadius: "8px",
    boxShadow: "0 4px 8px rgba(0, 0, 0, 0.1)",
  },
  header: {
    color: "#333",
    textAlign: "center",
    fontSize: "24px",
  },
  status: {
    textAlign: "center",
    fontSize: "18px",
    margin: "10px 0",
    color: "#444",
  },
  buttonContainer: {
    display: "flex",
    flexWrap: "wrap",
    justifyContent: "center",
    gap: "10px",
    marginBottom: "20px",
  },
  button: {
    padding: "10px 20px",
    fontSize: "14px",
    color: "#fff",
    backgroundColor: "#007bff",
    border: "none",
    borderRadius: "4px",
    cursor: "pointer",
  },
  messageBox: {
    marginBottom: "20px",
    padding: "10px",
    backgroundColor: "#e0e8f0",
    borderRadius: "4px",
    color: "#555",
  },
  summaryBox: {
    padding: "10px",
    backgroundColor: "#f9f9f9",
    borderRadius: "4px",
    color: "#444",
  },
  sectionHeader: {
    fontSize: "18px",
    color: "#333",
    marginBottom: "10px",
  },
};
