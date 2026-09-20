import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import api from "../api";

function Register() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");

  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();

    try {
      const response = await api.post("/register", {
        username,
        password,
      });

      if (response.data.success) {
        alert("Registered Succesfully");
        navigate("/login");
      } else {
        setMessage(response.data.message);
      }
    } catch (error) {
      setMessage("Unable to connect to server");
    }
  };

  return (
    <div className="page">
      <h1>Create Account</h1>

      <form onSubmit={handleRegister}>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />

        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <button type="submit">Register</button>
      </form>

      <p>{message}</p>

      <p>
        Already have an account? <Link to="/login">Login</Link>
      </p>

      <Link to="/">← Home</Link>
    </div>
  );
}

export default Register;