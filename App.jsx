import React from 'react';
import Dashboard from './dashboard';
import sampleData from './sampleData';

const App = () => {
    return (
        <div>
            <h1>Dashboard</h1>
            <Dashboard data={sampleData} />
        </div>
    );
};

export default App;
