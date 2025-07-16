import React, { useState } from "react";
import axios from "axios";
import {
    BarChart, Bar, XAxis, YAxis, Tooltip,
    CartesianGrid, ResponsiveContainer, Legend
} from 'recharts';

function UploadForm() {
    const [file, setFile] = useState(null);
    const [response, setResponse] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    const handleFileChange = (e) => {
        setFile(e.target.files[0]);
        setResponse(null);
        setError("");
    };

    const handleUpload = async () => {
        if (!file) {
            alert("Please select a file first");
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
        } catch (err) {
            setError("Upload failed: " + (err.response?.data?.detail || err.message));
        } finally {
            setLoading(false);
        }
    };

    return (
        <div>
            <h2>Upload PCAP File</h2>
            <input type="file" onChange={handleFileChange} />
            <button onClick={handleUpload}>Upload</button>

            {loading && <p>Uploading and processing file...</p>}
            {error && <p style={{ color: 'red' }}>{error}</p>}

            {response?.protocols && (
                <div style={{ marginTop: "2rem" }}>
                    <h3>Protocol Breakdown (Frames & Bytes)</h3>
                    <ResponsiveContainer width="100%" height={300}>
                        <BarChart data={response.protocols}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="protocol" />
                            <YAxis />
                            <Tooltip />
                            <Legend />
                            <Bar dataKey="frames" fill="#8884d8" name="Frames" />
                            <Bar dataKey="bytes" fill="#82ca9d" name="Bytes" />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            )}
        </div>
    );
}

export default UploadForm;
