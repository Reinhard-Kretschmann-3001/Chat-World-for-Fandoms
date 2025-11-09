// server.js (PHIÊN BẢN 2 - AN TOÀN)
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import mongoose from "mongoose";
import bcrypt from "bcryptjs"; // (MỚI) Chuyên gia Khóa
import jwt from "jsonwebtoken"; // (MỚI) Chuyên gia In Thẻ

// (MỚI) Nhập các "Sổ Sách"
import AuModel from "./models/AuModel.js"; // (MỚI) Đổi tên tệp này
import UserModel from "./models/User.js";   // (MỚI) Sổ Thành viên

// --- SỬA LỖI CORS (Giữ nguyên) ---
const PROD_ORIGIN = "https://divine-dustsans-404.github.io";
const DEV_ORIGIN = "http://localhost:2435";
const ALLOWED_ORIGINS = [PROD_ORIGIN, DEV_ORIGIN, "https://divine-dustsans-404.github.io/My-Aus-Wiki"];

// --- CÀI ĐẶT MÁY CHỦ (Giữ nguyên) ---
const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors({ origin: ALLOWED_ORIGINS }));
app.use(helmet());
app.use(morgan("tiny"));
app.use(express.json());

// --- KẾT NỐI DATABASE (Giữ nguyên) ---
const DB_CONNECTION_STRING = process.env.DATABASE_URI;
mongoose.connect(DB_CONNECTION_STRING)
  .then(() => console.log("Đã kết nối thành công với MongoDB!"))
  .catch((err) => {
    console.error("LỖI KẾT NỐI MONGODB:", err);
    process.exit(1);
  });

// --- (MỚI) LẤY BÍ MẬT IN THẺ ---
// Bạn PHẢI thêm biến này vào "Environment" trên Render
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("LỖI: JWT_SECRET chưa được cài đặt. Hãy thêm nó vào biến môi trường!");
  process.exit(1);
}

// --- (MỚI) MIDDLEWARE BẢO VỆ (Anh chàng Bảo vệ) ---
// Hàm này sẽ kiểm tra "Thẻ Thành viên" (Token)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Lấy thẻ (Token)

  if (token == null) {
    return res.status(401).json({ message: "Vui lòng đăng nhập để thực hiện việc này." }); // Không có thẻ
  }

  // Kiểm tra thẻ
  jwt.verify(token, JWT_SECRET, (err, userPayload) => {
    if (err) {
      return res.status(403).json({ message: "Thẻ thành viên không hợp lệ hoặc đã hết hạn." }); // Thẻ giả/hết hạn
    }
    
    // Nếu thẻ hợp lệ, lưu thông tin người dùng vào 'req'
    req.user = userPayload.user;
    next(); // Cho phép đi tiếp
  });
};


// --- (MỚI) CÁC TUYẾN ĐƯỜNG ĐĂNG KÝ / ĐĂNG NHẬP ---

// (MỚI) Route 1: ĐĂNG KÝ (Cửa Đăng Ký)
app.post("/auth/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: "Thiếu tên đăng nhập hoặc mật khẩu." });
  }

  try {
    const existingUser = await UserModel.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Tên đăng nhập này đã có người sử dụng." });
    }

    const newUser = new UserModel({ username, password });
    // "Chuyên gia Khóa" sẽ tự động băm mật khẩu (nhờ mã trong User.js)
    await newUser.save();
    
    res.status(201).json({ message: "Đăng ký thành công! Giờ bạn có thể đăng nhập." });
  } catch (err) {
    res.status(500).json({ message: "Lỗi máy chủ khi đăng ký." });
  }
});

// (MỚI) Route 2: ĐĂNG NHẬP (Cửa Đăng Nhập)
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await UserModel.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: "Sai tên đăng nhập hoặc mật khẩu." });
    }

    // "Chuyên gia Khóa" kiểm tra xem mật khẩu có khớp không
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Sai tên đăng nhập hoặc mật khẩu." });
    }

    // (MỚI) "Chuyên gia In Thẻ" tạo 1 Thẻ Thành viên (Token)
    const payload = {
      user: {
        id: user.id,
        username: user.username
      }
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '3h' }); // Thẻ có hạn 3 giờ

    res.json({
      message: "Đăng nhập thành công!",
      token: token, // Gửi thẻ về cho người dùng
      username: user.username
    });

  } catch (err) {
    res.status(500).json({ message: "Lỗi máy chủ khi đăng nhập." });
  }
});


// --- CÁC TUYẾN ĐƯỜNG VỀ AU (ĐÃ NÂNG CẤP) ---

// Route 3: Lấy danh sách tất cả AU (Giữ nguyên)
app.get("/aus", async (req, res) => {
  try {
    // Sửa: Thêm .populate() để lấy tên của người tạo
    const aus = await AuModel.find({}).sort({ created: -1 }).populate('createdBy', 'username');
    res.json(aus);
  } catch (err) {
    res.status(500).json({ message: "Lỗi máy chủ khi lấy dữ liệu." });
  }
});

// Route 4: Gửi (POST) một AU mới
// (NÂNG CẤP: Yêu cầu có "Bảo vệ" - authenticateToken)
app.post("/aus", authenticateToken, async (req, res) => {
  const { name, author, desc, link } = req.body;
  
  if (!name || !author || !desc) {
    return res.status(400).json({ message: "Thiếu dữ liệu Tên AU, Tác giả, hoặc Mô tả." });
  }

  try {
    const newAU = new AuModel({
      name: name,
      author: author,
      desc: desc,
      link: link || "",
      createdBy: req.user.id // (MỚI) Ký tên người tạo vào bài đăng
    });

    const savedAU = await newAU.save();
    res.status(201).json({ message: "Đã lưu AU thành công!", au: savedAU });
  } catch (err) {
    res.status(500).json({ message: "Lỗi máy chủ khi đang cố lưu dữ liệu." });
  }
});

// Route 5: XÓA (DELETE) MỘT AU
// (NÂNG CẤP: Yêu cầu "Bảo vệ" VÀ kiểm tra đúng chủ sở hữu)
app.delete("/aus/:id", authenticateToken, async (req, res) => {
  try {
    const auId = req.params.id;
    const au = await AuModel.findById(auId);

    if (!au) {
      return res.status(404).json({ message: "Không tìm thấy AU để xóa." });
    }

    // (MỚI) Kiểm tra xem bạn có phải là người tạo AU này không
    // (Chúng ta phải chuyển đổi .toString() vì kiểu dữ liệu của chúng khác nhau)
    if (au.createdBy.toString() !== req.user.id) {
      // 403: Forbidden (Cấm)
      return res.status(403).json({ message: "Bạn không có quyền xóa AU của người khác." });
    }

    // Nếu đúng là của bạn -> Xóa
    await AuModel.findByIdAndDelete(auId);
    res.status(200).json({ message: "Đã xóa AU thành công!" });

  } catch (err) {
    res.status(500).json({ message: "Lỗi máy chủ khi đang cố xóa." });
  }
});

// Route 6: Route gốc (Giữ nguyên)
app.get("/", (req, res) => {
  res.send(`<h2>DUSTTALE Backend (Phiên bản 2 - Bảo mật) đang chạy.</h2>`);
});

// Khởi động máy chủ (Giữ nguyên)
app.listen(PORT, () => {
  console.log(`Server hoạt động tại cổng ${PORT}`);
  console.log(`Đang chấp nhận yêu cầu từ: ${ALLOWED_ORIGINS.join(', ')}`);
});
