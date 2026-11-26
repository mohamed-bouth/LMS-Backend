import request from "supertest";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import app from "../src/app.js";
import User from "../src/models/User.js";
import {
  comparePassword,
  hashPassword,
} from "../src/utils/jwtHelper.js";

const TEST_URI =
  process.env.MONGO_URI_TEST ||
  "mongodb://127.0.0.1:27017/lms_test";

let admin;
let trainer;

async function createUser(role, email) {
  const user = await User.create({
    name: `${role} test`,
    email,
    password: "TestPassword123!",
    role,
    accountStatus: "active",
  });

  return {
    user,
    token: jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    ),
  };
}

beforeAll(async () => {
  await mongoose.connect(TEST_URI);
});

beforeEach(async () => {
  await User.deleteMany({});
  admin = await createUser("admin", "admin-users@test.com");
  trainer = await createUser("trainer", "trainer-users@test.com");
});

afterAll(async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
});

describe("Admin user management", () => {
  it("requires an admin to list users", async () => {
    const anonymousResponse = await request(app).get("/api/admin/users");
    const trainerResponse = await request(app)
      .get("/api/admin/users")
      .set("Authorization", `Bearer ${trainer.token}`);

    expect(anonymousResponse.status).toBe(401);
    expect(trainerResponse.status).toBe(403);
  });

  it("creates a user with a hashed password and no sensitive fields in the response", async () => {
    const response = await request(app)
      .post("/api/admin/users")
      .set("Authorization", `Bearer ${admin.token}`)
      .send({
        name: "  New Learner  ",
        email: "  NEW.LEARNER@test.com ",
        password: "LearnerPassword123",
      });

    expect(response.status).toBe(201);
    expect(response.body.data.user).toMatchObject({
      name: "New Learner",
      email: "new.learner@test.com",
      role: "learner",
      accountStatus: "active",
    });
    expect(response.body.data.user.password).toBeUndefined();
    expect(response.body.data.user.resetPasswordToken).toBeUndefined();

    const createdUser = await User.findOne({ email: "new.learner@test.com" })
      .select("+password");
    expect(createdUser.password).not.toBe("LearnerPassword123");
    await expect(
      comparePassword("LearnerPassword123", createdUser.password),
    ).resolves.toBe(true);
  });

  it("filters and paginates users without returning passwords", async () => {
    await User.create([
      {
        name: "Active Learner",
        email: "active-learner@test.com",
        password: "password123",
        role: "learner",
        accountStatus: "active",
      },
      {
        name: "Suspended Learner",
        email: "suspended-learner@test.com",
        password: "password123",
        role: "learner",
        accountStatus: "suspended",
      },
    ]);

    const response = await request(app)
      .get("/api/admin/users?role=learner&accountStatus=active&page=1&limit=1")
      .set("Authorization", `Bearer ${admin.token}`);

    expect(response.status).toBe(200);
    expect(response.body.data.users).toHaveLength(1);
    expect(response.body.data.users[0].role).toBe("learner");
    expect(response.body.data.users[0].accountStatus).toBe("active");
    expect(response.body.data.users[0].password).toBeUndefined();
    expect(response.body.data.pagination).toMatchObject({
      page: 1,
      limit: 1,
      total: 1,
      totalPages: 1,
    });
  });

  it("suspends users and prevents them from logging in", async () => {
    const learner = await User.create({
      name: "Learner",
      email: "learner-to-suspend@test.com",
      password: await hashPassword("password123"),
      role: "learner",
      accountStatus: "active",
    });

    const updateResponse = await request(app)
      .patch(`/api/admin/users/${learner._id}`)
      .set("Authorization", `Bearer ${admin.token}`)
      .send({ accountStatus: "suspended" });
    const loginResponse = await request(app)
      .post("/api/auth/login")
      .send({ email: learner.email, password: "password123" });

    expect(updateResponse.status).toBe(200);
    expect(updateResponse.body.data.user.accountStatus).toBe("suspended");
    expect(loginResponse.status).toBe(403);
  });

  it("does not allow removing the last active admin", async () => {
    const response = await request(app)
      .patch(`/api/admin/users/${admin.user._id}`)
      .set("Authorization", `Bearer ${admin.token}`)
      .send({ accountStatus: "suspended" });

    expect(response.status).toBe(400);
    expect((await User.findById(admin.user._id)).accountStatus).toBe("active");
  });
});
