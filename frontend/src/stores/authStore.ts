import { create } from "zustand";
import { UserRole } from "../types";

interface AuthState {
  isAuthenticated: boolean;
  token: string | null;
  userEmail: string | null;
  userRole: UserRole | null;
  setAuth: (token: string, email: string, role: UserRole) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  isAuthenticated: !!localStorage.getItem("phantom_token"),
  token: localStorage.getItem("phantom_token"),
  userEmail: localStorage.getItem("phantom_email"),
  userRole: (localStorage.getItem("phantom_role") as UserRole) || "SECURITY_ENGINEER",

  setAuth: (token: string, email: string, role: UserRole) => {
    localStorage.setItem("phantom_token", token);
    localStorage.setItem("phantom_email", email);
    localStorage.setItem("phantom_role", role);
    set({ isAuthenticated: true, token, userEmail: email, userRole: role });
  },

  logout: () => {
    localStorage.removeItem("phantom_token");
    localStorage.removeItem("phantom_email");
    localStorage.removeItem("phantom_role");
    set({ isAuthenticated: false, token: null, userEmail: null, userRole: null });
  },
}));

