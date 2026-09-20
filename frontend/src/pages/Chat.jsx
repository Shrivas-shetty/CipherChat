import { useNavigate } from "react-router-dom";
import api from "../api";


function Chat() {
  const navigate = useNavigate();
  const username = localStorage.getItem("username");

  const logout = async () => {
    try {
      await api.post("/logout", {
        username: username
      });

      // Remove login data after successful logout request
      localStorage.removeItem("token");
      localStorage.removeItem("username");

      navigate("/login");

    } catch (error) {
      console.error("Logout failed:", error);
    }
  };

  return (
    <div className="page">
      <h1>💬 CipherChat</h1>

      <h2>Welcome, {username}</h2>

      <p>Chat interface coming next.</p>

      <button onClick={logout}>Logout</button>
    </div>
  );
}

export default Chat;