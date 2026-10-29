import React, { useState, useEffect } from 'react';
import { API_BASE_URL } from '../config';

const AdminPanel = () => {
  const [users, setUsers] = useState([]);
  const [searchResults, setSearchResults] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookResult, setWebhookResult] = useState('');
  const [calcExpression, setCalcExpression] = useState('');
  const [calcResult, setCalcResult] = useState('');
  const [xmlData, setXmlData] = useState('');
  const [importResult, setImportResult] = useState('');
  const [announcements, setAnnouncements] = useState([]);
  const [newAnnouncement, setNewAnnouncement] = useState('');

  const token = localStorage.getItem('token');

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/admin/users`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setUsers(data);
      }
    } catch (error) {
      console.error('Failed to fetch users:', error);
    }
  };

  // Busqueda en memoria; los resultados se renderizan como TEXTO con React,
  // no con dangerouslySetInnerHTML (evita XSS). El filtrado es por subcadena.
  const handleSearch = (query) => {
    setSearchQuery(query);
    if (!query) {
      setSearchResults([]);
      return;
    }
    setSearchResults(users.filter((u) => u.username.includes(query)));
  };

  // Calculo local solo aritmetico, sin eval(). Se valida el formato y se usa
  // Function con una expresion ya saneada; ante cualquier caracter raro, error.
  const handleCalculate = () => {
    if (!/^[0-9+\-*/(). %]+$/.test(calcExpression)) {
      setCalcResult('Error: expresion no permitida');
      return;
    }
    try {
      // eslint-disable-next-line no-new-func
      const result = Function(`"use strict"; return (${calcExpression});`)();
      setCalcResult(String(result));
    } catch (e) {
      setCalcResult('Error: expresion invalida');
    }
  };

  // Los anuncios se guardan en estado y React los pinta como texto escapado.
  const renderAnnouncement = (text) => {
    if (!text) return;
    setAnnouncements((prev) => [...prev, text]);
    setNewAnnouncement('');
  };

  const testWebhook = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/admin/webhook-test`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ url: webhookUrl })
      });
      const data = await response.json();
      setWebhookResult(JSON.stringify(data, null, 2));
    } catch (error) {
      setWebhookResult('Error: ' + error.message);
    }
  };

  const importXml = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/admin/import-data`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/xml',
          'Authorization': `Bearer ${token}`
        },
        body: xmlData
      });
      const data = await response.json();
      setImportResult(JSON.stringify(data, null, 2));
    } catch (error) {
      setImportResult('Error: ' + error.message);
    }
  };

  return (
    <div className="max-w-6xl mx-auto p-6">
      <h1 className="text-3xl font-bold mb-8">Admin Panel</h1>

      <section className="bg-white rounded-lg shadow-md p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">User Search</h2>
        <input
          type="text"
          placeholder="Search users..."
          className="w-full p-2 border rounded mb-4"
          value={searchQuery}
          onChange={(e) => handleSearch(e.target.value)}
        />
        <div>
          {searchQuery && searchResults.length === 0 && (
            <p className="text-red-500">No results found for: <strong>{searchQuery}</strong></p>
          )}
          {searchResults.map((u) => (
            <div key={u.id} className="p-2 border-b">
              <strong>{u.username}</strong> - Balance: ${u.balance} - Role: {u.role}
            </div>
          ))}
        </div>
      </section>

      <section className="bg-white rounded-lg shadow-md p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">Announcements</h2>
        <div className="flex gap-2 mb-4">
          <input
            type="text"
            value={newAnnouncement}
            onChange={(e) => setNewAnnouncement(e.target.value)}
            placeholder="New announcement..."
            className="flex-1 p-2 border rounded"
          />
          <button
            onClick={() => renderAnnouncement(newAnnouncement)}
            className="px-4 py-2 bg-yellow-500 text-white rounded hover:bg-yellow-600"
          >
            Post
          </button>
        </div>
        <div id="announcements">
          {announcements.map((text, i) => (
            <div key={i} className="p-2 bg-yellow-50 border-l-4 border-yellow-400 mb-2">
              {text}
            </div>
          ))}
        </div>
      </section>

      <section className="bg-white rounded-lg shadow-md p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">Calculator</h2>
        <div className="flex gap-2">
          <input
            type="text"
            value={calcExpression}
            onChange={(e) => setCalcExpression(e.target.value)}
            placeholder="Enter expression..."
            className="flex-1 p-2 border rounded"
          />
          <button
            onClick={handleCalculate}
            className="px-4 py-2 bg-purple-600 text-white rounded hover:bg-purple-700"
          >
            Calculate
          </button>
        </div>
        {calcResult && <p className="mt-2 text-lg font-mono">Result: {calcResult}</p>}
      </section>

      <section className="bg-white rounded-lg shadow-md p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">Webhook Tester</h2>
        <div className="flex gap-2 mb-4">
          <input
            type="text"
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="Enter webhook URL..."
            className="flex-1 p-2 border rounded"
          />
          <button
            onClick={testWebhook}
            className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700"
          >
            Test
          </button>
        </div>
        {webhookResult && <pre className="bg-gray-100 p-4 rounded overflow-auto">{webhookResult}</pre>}
      </section>

      <section className="bg-white rounded-lg shadow-md p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">XML Data Import</h2>
        <textarea
          value={xmlData}
          onChange={(e) => setXmlData(e.target.value)}
          placeholder="Paste XML data..."
          className="w-full p-2 border rounded h-32 mb-4 font-mono"
        />
        <button
          onClick={importXml}
          className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700"
        >
          Import
        </button>
        {importResult && <pre className="mt-4 bg-gray-100 p-4 rounded overflow-auto">{importResult}</pre>}
      </section>

      <section className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-xl font-semibold mb-4">All Users</h2>
        <table className="min-w-full">
          <thead>
            <tr className="bg-gray-50">
              <th className="px-4 py-2 text-left">ID</th>
              <th className="px-4 py-2 text-left">Username</th>
              <th className="px-4 py-2 text-left">Email</th>
              <th className="px-4 py-2 text-left">Balance</th>
              <th className="px-4 py-2 text-left">Role</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id} className="border-b">
                <td className="px-4 py-2">{user.id}</td>
                <td className="px-4 py-2">{user.username}</td>
                <td className="px-4 py-2">{user.email}</td>
                <td className="px-4 py-2">${user.balance}</td>
                <td className="px-4 py-2">{user.role}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
};

export default AdminPanel;
