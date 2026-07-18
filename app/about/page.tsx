import AppBar from "../components/AppBar";

import * as React from "react";
import List from "@mui/material/List";
import ListItem from "@mui/material/ListItem";
import ListItemAvatar from "@mui/material/ListItemAvatar";
import ListItemText from "@mui/material/ListItemText";
import Avatar from "@mui/material/Avatar";
import IconButton from "@mui/material/IconButton";
import Typography from "@mui/material/Typography";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import DatasetLinkedIcon from "@mui/icons-material/DatasetLinked";

const resources = [
  {
    primary: "hpke.dev",
    secondary: "HPKE Interoperability for JOSE and COSE ",
    link: "https://github.com/transmute-industries/hpke.dev",
  },
  {
    primary: "Hybrid Public Key Encryption",
    secondary: "RFC 9180",
    link: "https://datatracker.ietf.org/doc/rfc9180/",
  },
  {
    primary: "Use of Hybrid Public-Key Encryption (HPKE) with CBOR Object Signing and Encryption (COSE)",
    secondary: "draft-ietf-cose-hpke",
    link: "https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/",
  },
  {
    primary: "Use of Hybrid Public-Key Encryption (HPKE) with Javascript Object Signing and Encryption (JOSE)",
    secondary: "draft-ietf-jose-hpke-encrypt",
    link: "https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/",
  },
  {
    primary: "hpke",
    secondary: "Hybrid Public Key Encryption (HPKE) for Node.js, Browser, Deno, Bun, and other Web-interoperable runtimes.",
    link: "https://github.com/panva/hpke",
  },
  {
    primary: "t_cose",
    secondary: "Commercial quality COSE_Sign1 implementation in C for constrained environment. Works with MbtedTLS and OpenSSL Crypto.",
    link: "https://github.com/laurencelundblade/t_cose",
  },
];

export default function About() {
  return (
    <AppBar>
      <Typography sx={{ mb: 2 }} variant="h6" component="div">
        Resources
      </Typography>
      <List>
        {resources.map((resource) => {
          return (
            <ListItem
              key={resource.link}
              secondaryAction={
                <IconButton edge="end" aria-label="open" href={resource.link}>
                  <OpenInNewIcon />
                </IconButton>
              }
            >
              <ListItemAvatar>
                <Avatar>
                  <DatasetLinkedIcon />
                </Avatar>
              </ListItemAvatar>
              <ListItemText
             
                primary={resource.primary}
                secondary={resource.secondary}
              />
            </ListItem>
          );
        })}
      </List>
    </AppBar>
  );
}
