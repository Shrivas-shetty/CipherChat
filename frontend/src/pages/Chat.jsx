import { useNavigate } from "react-router-dom";

function Chat() {
  const navigate = useNavigate();
  const username = localStorage.getItem("username");

  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("username");

    navigate("/login");
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