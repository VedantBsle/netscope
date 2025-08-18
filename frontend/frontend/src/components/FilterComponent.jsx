import React, { useState, useEffect } from "react";

function FilterComponent({ data, onFilter }) {
    const [filterText, setFilterText] = useState("");

    useEffect(() => {
        if (!data) return;

        const lowerFilter = filterText.toLowerCase();

        const filtered = {
            ...data,
            protocols: data.protocols.filter((p) =>
                !filterText
                    ? true
                    : (p.protocol && String(p.protocol).toLowerCase().includes(lowerFilter))

            ),
            ip_conversations: data.ip_conversations.filter((conv) =>
                !filterText
                    ? true
                    : (conv.source &&
                        conv.source.toLowerCase().includes(lowerFilter)) ||
                    (conv.destination &&
                        conv.destination.toLowerCase().includes(lowerFilter)) ||
                    (conv.protocol &&
                        String(conv.protocol).toLowerCase().includes(lowerFilter))
            ),
        };

        onFilter(filtered);
    }, [filterText, data, onFilter]);

    return (
        <div
            className="card"
            style={{ width: "100%", maxWidth: "700px", marginBottom: "2rem" }}
        >
            <h3>Filter Data</h3>

            <input
                type="text"
                placeholder="Enter filter (e.g., tcp, udp, 192.168.1.1)"
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                style={{
                    width: "100%",
                    padding: "0.5rem",
                    borderRadius: "5px",
                    border: "1px solid #444",
                    backgroundColor: "#2e2e2e",
                    color: "white",
                }}
            />
        </div>
    );
}

export default FilterComponent;
