import React from "react";

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="w-full max-w-95 flex flex-col items-center">
      {children}
    </div>
  );
}
