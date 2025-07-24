import React, { useState, useEffect } from 'react';

function FilterComponent({ data, onFilter }) {
    const [protocol, setProtocol] = useState('');
    const [minBytes, setMinBytes] = useState(0);

    useEffect(() => {
        if (!data) return;

        // Apply filtering
        const filtered = {
            ...data,
            protocols: data.protocols.filter(p =>
                (protocol ? p.protocol === protocol : true) &&
                (p.bytes >= minBytes)
            ),
            ip_conversations: data.ip_conversations.filter(conv =>
                conv.bytes >= minBytes
            )
        };

        onFilter(filtered);
    }, [protocol, minBytes, data]);

    const protocolOptions = data?.protocols.map(p => p.protocol);

    return (
        <div className="card" style={{ width: '100%', maxWidth: '700px', marginBottom: '2rem' }}>
            <h3>Filter Data</h3>

            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                <div>
                    <label>Protocol:</label><br />
                    <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
                        <option value="">All</option>
                        {protocolOptions?.map((proto, idx) => (
                            <option key={idx} value={proto}>{proto}</option>
                        ))}
                    </select>
                </div>

                <div>
                    <label>Min Bytes:</label><br />
                    <input
                        type="number"
                        value={minBytes}
                        onChange={(e) => setMinBytes(Number(e.target.value))}
                        min="0"
                    />
                </div>
            </div>
        </div>
    );
}

export default FilterComponent;
