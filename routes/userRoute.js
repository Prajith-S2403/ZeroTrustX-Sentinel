import { Navigate } from "react-router-dom";

function UserRoute({ children }) {
  const token = localStorage.getItem("token");

  if (!token) {
    return <Navigate to="/" />;
  }

  return children;
}

export default UserRoute;