# Node agent

Configure `/etc/unified-vps/agent.env`:

```
UVPS_CONTROL_PLANE_URL=https://control.example.com
UVPS_SERVER_ID=<server-id>
UVPS_NODE_TOKEN=<one-time-token>
```

The token is never written into Git. The agent accepts only typed command names implemented in `COMMAND_HANDLERS`; it does not evaluate shell strings received from the network.