import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import App from "../src/app/App";

describe("PHANTOM-X Frontend Foundation", () => {
  it("renders the dashboard layout and title properly", () => {
    render(<App />);
    expect(screen.getByText("PHANTOM-X")).toBeInTheDocument();
    expect(screen.getByText("Security Intelligence Command")).toBeInTheDocument();
  });

  it("displays the OBSERVE safety mode badge", () => {
    render(<App />);
    expect(screen.getByText("OBSERVE")).toBeInTheDocument();
  });
});

