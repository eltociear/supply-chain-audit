class SSHManager:
    async def setup(self):
        await self.execute_command("systemctl enable unas-agent")

    async def execute_command(self, cmd):
        return await self._conn.run(cmd)
