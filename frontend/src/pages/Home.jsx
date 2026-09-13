import { Link } from "react-router-dom";

function Home() {
  const token = localStorage.getItem("token");

  return (
    <div className="page">
      <h1>🔐 CipherChat</h1>

      <p>Secure communication over a local network.</p>

      <div className="buttons">
        {token ? (
          <Link to="/chat">
            <button>Open Chat</button>
          </Link>
        ) : (
          <>
            <Link to="/login">
              <button>Login</button>
            </Link>

            <Link to="/register">
              <button>Register</button>
            </Link>
          </>
        )}
      </div>
    </div>
  );
}

export default Home;