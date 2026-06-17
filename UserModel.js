// models/JsonUserModel.js
const fs = require("fs/promises");

class JsonUserModel
{
    constructor(filePath)
    {
        this.filePath = filePath;
    }

    async findByUsername(username)
    {
        const users = await this.readAll();

        return users.find((user) => user.username === username) ?? null;
    }

    async save(user)
    {
        const users = await this.readAll();
        users.push(user);

        await fs.writeFile(this.filePath, JSON.stringify(users, null, 4));
    }

    async readAll()
    {
        const content = await fs.readFile(this.filePath, "utf8");

        return JSON.parse(content);
    }
}

module.exports = JsonUserModel; 