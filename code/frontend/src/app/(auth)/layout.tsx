import React from "react";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-[#ebebeb] p-6 font-sans text-[#111]">
      <div className="w-full max-w-[380px] animate-in fade-in slide-in-from-bottom-3 duration-300 ease-out">
        <div className="w-full">
          {children}
        </div>
      </div>
    </div>
  );
}
