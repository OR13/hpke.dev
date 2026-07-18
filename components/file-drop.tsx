"use client";

import { useCallback } from "react";
import { useDropzone } from "react-dropzone";
import { UploadSimpleIcon } from "@phosphor-icons/react";

import { cn } from "@/lib/utils";

export function FileDrop({
  dragText = "Drag a key file here",
  dropText = "Drop to load.",
  onFilesAccepted,
}: {
  dragText?: string;
  dropText?: string;
  onFilesAccepted: (files: File[]) => void;
}) {
  const onDrop = useCallback(
    (accepted: File[]) => onFilesAccepted(accepted),
    [onFilesAccepted],
  );
  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop });

  return (
    <div
      {...getRootProps()}
      className={cn(
        "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border bg-muted/30 px-6 py-10 text-center text-sm text-muted-foreground transition-colors hover:border-foreground/40 hover:bg-muted/50",
        isDragActive && "border-foreground/60 bg-muted",
      )}
    >
      <input {...getInputProps()} />
      <UploadSimpleIcon className="size-6" weight="bold" />
      <span>{isDragActive ? dropText : dragText}</span>
      <span className="text-xs text-muted-foreground/70">or click to choose a file</span>
    </div>
  );
}
