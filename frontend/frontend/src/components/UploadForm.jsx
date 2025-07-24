import React, { useState, useRef } from "react";
import axios from "axios";
import {
    BarChart, Bar, XAxis, YAxis, Tooltip,
    CartesianGrid, ResponsiveContainer, Legend
} from 'recharts';
import FilterComponent from "./FilterComponent";
import '../styles/styles.css';

function UploadForm() {
    const [file, setFile] = useState(null);
    const [response, setResponse] = useState(null);
    const [filteredResponse, setFilteredResponse] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const fileInputRef = useRef();

    const handleFileChange = (e) => {
        setFile(e.target.files[0]);
        setResponse(null);
        setFilteredResponse(null);
        setError("");
    };

    const handleUpload = async () => {
        if (!file) {
            alert("Please select a PCAP or PCAPNG file");
            return;
        }

        const formData = new FormData();
        formData.append("file", file);

        try {
            setLoading(true);
            setError("");
            const res = await axios.post("http://127.0.0.1:8000/upload", formData, {
                headers: {
                    "Content-Type": "multipart/form-data",
                },
            });
            setResponse(res.data);
            setFilteredResponse(res.data); // default filtered = full
        } catch (err) {
            setError("Upload failed: " + (err.response?.data?.detail || err.message));
        } finally {
            setLoading(false);
        }
    };

    const handleDrop = (e) => {
        e.preventDefault();
        if (e.dataTransfer.files.length) {
            setFile(e.dataTransfer.files[0]);
            setResponse(null);
            setFilteredResponse(null);
            setError("");
        }
    };

    const handleDragOver = (e) => {
        e.preventDefault();
    };

    const downloadFilteredJSON = () => {
        const element = document.createElement('a');
        const file = new Blob([JSON.stringify(filteredResponse, null, 2)], { type: 'application/json' });
        element.href = URL.createObjectURL(file);
        element.download = 'filtered_summary.json';
        document.body.appendChild(element);
        element.click();
        document.body.removeChild(element);
    };

    return (
        <div className="upload-form-container">
            <h1 className="title">PCAP-Viz: Packet Analyzer</h1>

            {/* Dropzone */}
            <div
                className="dropzone card"
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onClick={() => fileInputRef.current.click()}
            >
                <p>{file ? `Selected: ${file.name}` : "Drag & drop a PCAP file here or click to browse"}</p>
                <input
                    type="file"
                    accept=".pcap,.pcapng"
                    onChange={handleFileChange}
                    ref={fileInputRef}
                    style={{ display: "none" }}
                />
            </div>

            <button className="upload-btn" onClick={handleUpload}>
                Upload
            </button>

            {loading && <p className="status-msg">Uploading and processing file...</p>}
            {error && <p className="error-msg">{error}</p>}

            {/* FilterComponent */}
            {response && (
                <FilterComponent data={response} onFilter={setFilteredResponse} />
            )}

            {/* Summary */}
            {filteredResponse?.packet_summary && (
                <div className="summary-block card">
                    <h3>Packet Summary</h3>
                    <p><strong>Total Packets:</strong> {filteredResponse.packet_summary.total_packets}</p>
                    <p><strong>Total Bytes:</strong> {filteredResponse.packet_summary.total_bytes}</p>
                </div>
            )}

            {/* Protocol Chart */}
            {filteredResponse?.protocols && (
                <div className="summary-block card">
                    <h3>Protocol Breakdown (Packets & Bytes)</h3>
                    <ResponsiveContainer width="100%" height={300}>
                        <BarChart data={filteredResponse.protocols}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="protocol" />
                            <YAxis />
                            <Tooltip />
                            <Legend />
                            <Bar dataKey="packets" fill="#8884d8" name="Packets" />
                            <Bar dataKey="bytes" fill="#82ca9d" name="Bytes" />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            )}

            {/* IP Conversations */}
            {filteredResponse?.ip_conversations?.length > 0 && (
                <div className="summary-block card">
                    <h3>IP Conversations</h3>
                    <table className="ip-table">
                        <thead>
                            <tr>
                                <th>Source</th>
                                <th>Destination</th>
                                <th>Bytes</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredResponse.ip_conversations.map((conv, index) => (
                                <tr key={index}>
                                    <td>{conv.source}</td>
                                    <td>{conv.destination}</td>
                                    <td>{conv.bytes}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}

            {/* Download Filtered JSON */}
            {filteredResponse && (
                <div className="centered-section">
                    <button className="download-btn" onClick={downloadFilteredJSON}>
                        Download Filtered JSON
                    </button>
                </div>
            )}
        </div>
    );
}

export default UploadForm;
