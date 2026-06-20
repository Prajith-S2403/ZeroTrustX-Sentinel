import { Navigate } from "react-router-dom";

function AdminRoute({ children }) {
  const token = localStorage.getItem("token");
  const user = JSON.parse(localStorage.getItem("user"));

  if (!token) {
    return <Navigate to="/" />;
  }

  if (user?.role !== "admin") {
    return <Navigate to="/dashboard" />;
  }

  return children;
}

export default AdminRoute;