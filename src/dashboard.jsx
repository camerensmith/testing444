// React/Recharts dashboard code
import React from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';

const Dashboard = ({ data }) => {
    return (
        <LineChart width={600} height={300} data={data}>
            <XAxis dataKey="name" />
            <YAxis />
            <Tooltip />
            <CartesianGrid strokeDasharray="3 3" />
            <Line type="monotone" dataKey="value" stroke="#8884d8" />
        </LineChart>
    );
};

export default Dashboard;
