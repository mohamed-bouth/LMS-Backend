import User from "../models/User.js";
import { hashPassword } from "../utils/jwtHelper.js";
import {
  NotFoundError,
  ValidationError,
} from "../utils/errors.js";

const userFields = "_id name email role accountStatus createdAt updatedAt";
const roles = ["learner", "trainer", "admin"];
const accountStatuses = ["active", "suspended"];
const mutableFields = ["name", "email", "role", "accountStatus"];

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function getPaginationValue(value, defaultValue, maximum = Number.MAX_SAFE_INTEGER) {
  if (value === undefined) {
    return defaultValue;
  }

  if (!/^\d+$/.test(value)) {
    return null;
  }

  const parsedValue = Number(value);
  return parsedValue >= 1 && parsedValue <= maximum ? parsedValue : null;
}

function validateUserFields(fields) {
  if (fields.name !== undefined) {
    if (typeof fields.name !== "string" || !fields.name.trim()) {
      return "Name must be a non-empty string.";
    }
    fields.name = fields.name.trim();
  }

  if (fields.email !== undefined) {
    if (typeof fields.email !== "string" || !isValidEmail(fields.email.trim())) {
      return "A valid email is required.";
    }
    fields.email = fields.email.trim().toLowerCase();
  }

  if (fields.role !== undefined && !roles.includes(fields.role)) {
    return "Role must be learner, trainer or admin.";
  }

  if (
    fields.accountStatus !== undefined &&
    !accountStatuses.includes(fields.accountStatus)
  ) {
    return "Account status must be active or suspended.";
  }

  return null;
}

export async function listUsers(req, res, next) {
  try {
    const page = getPaginationValue(req.query.page, 1);
    const limit = getPaginationValue(req.query.limit, 20, 100);
    const { role, accountStatus, search } = req.query;

    if (!page || !limit) {
      return next(
        new ValidationError("Page must be positive and limit must be between 1 and 100."),
      );
    }

    if (role !== undefined && !roles.includes(role)) {
      return next(new ValidationError("Invalid role filter."));
    }

    if (
      accountStatus !== undefined &&
      !accountStatuses.includes(accountStatus)
    ) {
      return next(new ValidationError("Invalid account status filter."));
    }

    if (
      search !== undefined &&
      (typeof search !== "string" || search.trim().length > 100)
    ) {
      return next(new ValidationError("Search must be 100 characters or fewer."));
    }

    const filter = {};
    if (role) filter.role = role;
    if (accountStatus) filter.accountStatus = accountStatus;
    if (search?.trim()) {
      const searchPattern = new RegExp(escapeRegex(search.trim()), "i");
      filter.$or = [{ name: searchPattern }, { email: searchPattern }];
    }

    const [users, total] = await Promise.all([
      User.find(filter)
        .select(userFields)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit),
      User.countDocuments(filter),
    ]);

    return res.status(200).json({
      success: true,
      data: {
        users,
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit),
        },
      },
    });
  } catch (error) {
    next(error);
  }
}

export async function getUser(req, res, next) {
  try {
    const user = await User.findById(req.params.userId).select(userFields);

    if (!user) {
      return next(new NotFoundError("User not found."));
    }

    return res.status(200).json({
      success: true,
      data: { user },
    });
  } catch (error) {
    next(error);
  }
}

export async function createUser(req, res, next) {
  try {
    const body = req.body || {};
    const allowedFields = ["name", "email", "password", "role", "accountStatus"];

    if (
      Array.isArray(body) ||
      typeof body !== "object" ||
      Object.keys(body).some((field) => !allowedFields.includes(field))
    ) {
      return next(new ValidationError("Provide only valid user fields."));
    }

    const { name, email, password } = body;
    if (!name || !email || !password) {
      return next(
        new ValidationError("Name, email and password are required."),
      );
    }

    if (typeof password !== "string" || password.length < 8) {
      return next(
        new ValidationError("Password must contain at least 8 characters."),
      );
    }

    const fields = {
      name,
      email,
      role: body.role ?? "learner",
      accountStatus: body.accountStatus ?? "active",
    };
    const validationMessage = validateUserFields(fields);
    if (validationMessage) {
      return next(new ValidationError(validationMessage));
    }

    const user = await User.create({
      ...fields,
      password: await hashPassword(password),
    });

    return res.status(201).json({
      success: true,
      message: "User created successfully.",
      data: {
        user,
      },
    });
  } catch (error) {
    next(error);
  }
}

export async function updateUser(req, res, next) {
  try {
    const body = req.body || {};

    if (
      Array.isArray(body) ||
      typeof body !== "object" ||
      Object.keys(body).length === 0 ||
      Object.keys(body).some((field) => !mutableFields.includes(field))
    ) {
      return next(new ValidationError("Provide valid user fields to update."));
    }

    const updates = { ...body };
    const validationMessage = validateUserFields(updates);
    if (validationMessage) {
      return next(new ValidationError(validationMessage));
    }

    const user = await User.findById(req.params.userId);
    if (!user) {
      return next(new NotFoundError("User not found."));
    }

    const wasActiveAdmin =
      user.role === "admin" && user.accountStatus === "active";
    Object.assign(user, updates);

    if (
      wasActiveAdmin &&
      (user.role !== "admin" || user.accountStatus !== "active")
    ) {
      const activeAdmins = await User.countDocuments({
        role: "admin",
        accountStatus: "active",
        _id: { $ne: user._id },
      });

      if (activeAdmins === 0) {
        return next(
          new ValidationError("At least one active admin must remain."),
        );
      }
    }

    await user.save();

    return res.status(200).json({
      success: true,
      message: "User updated successfully.",
      data: {
        user,
      },
    });
  } catch (error) {
    next(error);
  }
}
