// === Import các module cần thiết ===
const path = require("node:path"); // Xử lý đường dẫn file và thư mục
const fs = require("fs"); // Làm việc với hệ thống tệp (file system)
const { createHmac, randomBytes } = require("node:crypto"); // Tạo HMAC và số ngẫu nhiên (salt)
const { ObjectId } = require("@fastify/mongodb"); // Làm việc với ObjectId trong MongoDB

// === Import các module liên quan đến xác thực ===
const auth = require("./auth"); // Module xác thực người dùng
const authority = require("./authority"); // Kiểm tra quyền hạn người dùng (vd: quyền admin)

// === Tạo ứng dụng Fastify với cấu hình ===
const fastifyApp = require("fastify")({
    logger: true, // Bật tính năng ghi log cho ứng dụng
    bodyLimit: 150 * 1024 * 1024 // Giới hạn dung lượng của request body (150MB)
});

// === Đăng ký các plugin hỗ trợ ===
fastifyApp.register(require("@fastify/multipart")); // Xử lý multipart/form-data (upload file)
fastifyApp.register(require("@fastify/formbody")); // Xử lý application/x-www-form-urlencoded
fastifyApp.register(require("@fastify/mongodb"), { // Kết nối MongoDB
    forceClose: true, // Đảm bảo kết nối đóng khi server ngừng
    url: "mongodb://localhost:27017/databikedb" // URL kết nối đến MongoDB (CSDL: databikedb)
});

// === Đăng ký Pug làm engine render view ===
fastifyApp.register(require("@fastify/view"), {
    engine: {
        pug: require("pug") // Sử dụng engine Pug
    },
    root: "views", // Thư mục chứa các tệp template Pug
    propertyName: "render" // Sử dụng phương thức `render` để render view
});

// === Đăng ký xử lý file tĩnh (static files) ===
fastifyApp.register(require("@fastify/static"), {
    root: path.join(__dirname, "public"), // Thư mục chứa file tĩnh (CSS, JS, ảnh, v.v.)
    prefix: "/static/" // URL prefix cho các file tĩnh (vd: /static/style.css)
});

// === Đăng ký xử lý JWT (JSON Web Token) ===
fastifyApp.register(require("@fastify/jwt"), {
    secret: "uaihgfubjfksdfbsdkfbk" // Secret key để mã hóa và giải mã JWT
});

// === Đăng ký xử lý cookie ===
fastifyApp.register(require("@fastify/cookie"), {
    secret: "afdafwertgdfgbcvhbdfghed", // Secret key để mã hóa cookie
    hook: "onRequest" // Hook xử lý cookie trước khi thực hiện yêu cầu
});



//================================================= LOGIN & LOGOUT ====================================================================================================
// === Route hiển thị trang đăng nhập (GET) ===
fastifyApp.get("/login", function(req, rep) {
    let message = null; // Thông báo lỗi nếu có
    let username = null; // Tên đăng nhập người dùng nhập trước đó
    let url = null; // URL để chuyển hướng sau khi đăng nhập thành công (nếu có)

    // Kiểm tra lỗi đăng nhập dựa trên query string
    switch (req.query.err) {
        case "UserNotExist":
            message = 'Tên đăng nhập của bạn sai hoặc không tồn tại'; // Lỗi: Tài khoản không tồn tại
            username = req.query.username; // Giữ lại tên người dùng đã nhập
            break;
        case "WrongPass":
            message = "Mật khẩu sai, vui lòng nhập lại !!!"; // Lỗi: Sai mật khẩu
            username = req.query.username;
            break;
        case "unAuth":
            message = "Bạn cần đăng nhập để tiếp tục truy cập"; // Lỗi: Chưa đăng nhập
            url = req.query.url; // URL người dùng đang cố gắng truy cập
            break;
        case "unAuthority":
            message = `Bạn cần đăng nhập với quyền ${req.query.role} để tiếp tục truy cập`; // Lỗi: Không đủ quyền hạn
            url = req.query.url;
            break;
        default:
            break;
    }

    // Render trang login và truyền dữ liệu thông báo lỗi
    rep.render("login", { message, username, url });
});


// === Route xử lý đăng nhập (POST) ===
fastifyApp.post("/login", async function(req, rep) {
    // Tìm người dùng trong MongoDB bằng tên đăng nhập
    const user = await this.mongo.db.collection("users").findOne({ username: req.body.username });

    if (user) {
        // Mã hóa mật khẩu người dùng nhập vào để kiểm tra
        const newHpass = createHmac("sha256", user.salt).update(req.body.password).digest("hex");

        if (newHpass === user.hpass) {
            // Mật khẩu đúng -> Tạo JWT token
            const token = this.jwt.sign({ username: user.username, role: user.role, id: user._id.toString() });

            // Lưu token vào cookie
            rep.cookie("token", token);

            // Redirect đến URL đã yêu cầu trước đó hoặc về trang chủ
            if (req.query.url) rep.redirect(req.query.url);
            else rep.redirect("/");
        } else {
            // Sai mật khẩu -> Quay lại trang login với thông báo lỗi
            rep.redirect(`/login?err=WrongPass&username=${req.body.username}`);
        }
    } else {
        // Người dùng không tồn tại -> Quay lại trang login với thông báo lỗi
        rep.redirect(`/login?err=UserNotExist&username=${req.body.username}`);
    }
});


// === Route đăng xuất (GET) ===
fastifyApp.get('/logout', { onRequest: auth }, function(req, rep) {
    // Xóa cookie lưu JWT token
    rep.clearCookie('token');
    // Redirect về trang login
    rep.redirect('/login');
    return rep;
});



//================================================= USER-GIAO DIỆN MENU BAR ====================================================================================================
// === Route Trang Chủ ==
// Ý Nghĩa: Hiển thị trang chủ với danh sách xe máy hiện có.
fastifyApp.get('/', async function(req, rep) {
    const page = parseInt(req.query.page) || 1; // Lấy số trang từ query hoặc mặc định là 1
    const limit = parseInt(req.query.limit) || 3; // Lấy giới hạn sản phẩm mỗi trang, mặc định là 5
    const skip = (page - 1) * limit; // Tính toán số sản phẩm cần bỏ qua

    // Lọc các sản phẩm có SaleTag là "NEW PRODUCTS" và áp dụng phân trang
    const motos = await this.mongo.db.collection("motos")
        .find({ SaleTag: "NEW PRODUCTS" })
        .skip(skip)
        .limit(limit)
        .toArray();

    // Lấy tổng số sản phẩm có SaleTag là "NEW PRODUCTS"
    const totalMotos = await this.mongo.db.collection("motos")
        .find({ SaleTag: "NEW PRODUCTS" })
        .count();

    // Tính tổng số trang
    const totalPages = Math.ceil(totalMotos / limit);

    // Truyền dữ liệu vào template
    const { success, error, info } = req.query;
    rep.render('home', {
        motos,
        messages: {
            success,
            error,
            info,
        },
        isLoggedIn: req.user !== undefined,
        username: req.user ? req.user.username : null,
        currentPage: page,
        totalPages: totalPages
    });
    return rep;
});



// == Route Hãng Xe (automaker) ==
fastifyApp.get('/automaker', async function(req, rep) {
    const db = this.mongo.db;

    // Lấy các tham số từ query
    const { brand = "All", type = "All", page = 1, success, error, info } = req.query;
    const limit = 8; // Số lượng xe hiển thị mỗi trang
    const currentPage = parseInt(page) || 1; // Trang hiện tại
    const skip = (currentPage - 1) * limit; // Số lượng xe bỏ qua để phân trang

    // Tạo bộ lọc tìm kiếm theo hãng xe và dòng xe
    const query = {};
    if (brand !== "All") {
        query.HangXe = brand; // Lọc theo hãng xe
    }
    if (type !== "All") {
        query.DongXe = type; // Lọc theo dòng xe
    }

    // Lấy danh sách xe và tổng số lượng xe từ MongoDB
    const motos = await db.collection("motos").find(query).skip(skip).limit(limit).toArray();
    const totalMotos = await db.collection("motos").countDocuments(query); // Tổng số lượng xe phù hợp
    const totalPages = Math.ceil(totalMotos / limit); // Tổng số trang

    // Render giao diện automaker.pug
    rep.render('automaker', {
        motos, // Danh sách xe sau khi lọc
        selectedBrand: brand, // Hãng xe đã chọn
        selectedType: type, // Dòng xe đã chọn
        currentPage, // Trang hiện tại
        totalPages, // Tổng số trang
        messages: { success, error, info },
        isLoggedIn: req.user !== undefined,
        username: req.user ? req.user.username : null,
    });

    return rep;
});



// == Route hiển thị trang liên hệ (contact) ==
fastifyApp.get("/contact", async function(req, rep) {
    // Render trang liên hệ
    return rep.render('contact');
});

// == Route hiển thị trang Sản Phẩm ==
fastifyApp.get("/product", async function(req, rep) {
    // Render 
    return rep.render('product');
});

fastifyApp.get("/new", async function(req, rep) {
    // Render 
    return rep.render('new');
});


//================================================= TẠO NGƯỜI DÙNG (ADMIN/USER) ====================================================================================================
// === Route hiển thị giao diện tạo người dùng mới (GET) ===
// Ý nghĩa: Cung cấp giao diện để tạo tài khoản mới, thường dành cho admin hoặc tự đăng ký.
fastifyApp.get("/create-user", function(req, rep) {
    rep.render("create-user"); // Render trang form tạo người dùng
});


// === Route xử lý việc tạo người dùng mới (POST) ===
// Ý nghĩa: Xử lý dữ liệu người dùng nhập vào để tạo một tài khoản mới trong cơ sở dữ liệu.
fastifyApp.post("/user", async function(req, rep) {
    const { username, password, NgaySinh, SoDT, email, role } = req.body; // Nhận thông tin từ form

    // Kiểm tra nhập liệu
    if (!username || !password || !NgaySinh || !SoDT || !email) {
        return rep.render("create-user", { error: "Vui lòng nhập đầy đủ thông tin" }); // Thông báo nếu thiếu thông tin
    }

    // Kiểm tra tên đăng nhập trùng lặp
    const existingUser = await this.mongo.db.collection("users").findOne({ username });
    if (existingUser) {
        return rep.render("create-user", { error: "Tên đăng nhập đã tồn tại" });
    }

    // Kiểm tra ngày sinh hợp lệ
    const birthDate = new Date(NgaySinh);
    if (birthDate >= new Date()) {
        return rep.render("create-user", { error: "Ngày sinh phải nhỏ hơn ngày hiện tại" });
    }

    // Kiểm tra số điện thoại hợp lệ
    const phoneRegex = /^[0-9]{10}$/;
    if (!phoneRegex.test(SoDT)) {
        return rep.render("create-user", {
            error: "Số điện thoại phải có 10 chữ số",
            user: req.body, // Giữ lại dữ liệu đã nhập
        });
    }

    // Mã hóa mật khẩu
    const salt = randomBytes(16).toString("hex");
    const hpass = createHmac("sha256", salt).update(password).digest("hex");

    try {
        // Thêm người dùng mới vào MongoDB
        const result = await this.mongo.db.collection("users").insertOne({
            username,
            NgaySinh,
            SoDT,
            email,
            role,
            salt,
            hpass,
        });

        // Redirect đến trang đăng nhập nếu thành công
        rep.redirect("/login");
    } catch (error) {
        console.error("Lỗi khi tạo người dùng:", error);
        return rep.render("create-user", { error: "Đã xảy ra lỗi khi tạo người dùng" });
    }
});


















//================================================= ROUTES ADMIN & CONTACT ======================================================
// Route hiển thị trang admin (chỉ dành cho người dùng có quyền admin)
fastifyApp.get("/admin", { onRequest: [auth, authority("admin")] }, async function(req, rep) {
    // Kiểm tra xem người dùng đã đăng nhập chưa và có quyền admin không
    // Render trang admin với thông tin người dùng hiện tại
    rep.render('admin', {
        isLoggedIn: req.user !== undefined, // Kiểm tra người dùng có đăng nhập không
        username: req.user ? req.user.username : null // Nếu người dùng đăng nhập, truyền tên người dùng vào trang
    });
    return rep;
});





//================================================= (ADMIN)-QUẢN LÝ USER ====================================================================================================
// Route lấy danh sách người dùng (chỉ cho phép admin)
fastifyApp.get("/users", { onRequest: [auth, authority("admin")] }, async function(req, rep) {
    const users = await this.mongo.db.collection("users").find({}, { projection: { password: 0 } }).toArray(); // Lấy danh sách người dùng, không bao gồm mật khẩu
    rep.render("users", { users }); // Render view users.pug với danh sách người dùng
    return rep;
});


// Route để cập nhật thông tin người dùng
fastifyApp.get("/update-user/:id", { onRequest: [auth, authority("admin")] }, async function(req, rep) {
    const user = await this.mongo.db.collection("users").findOne({ _id: new ObjectId(req.params.id) }); // Lấy thông tin người dùng từ MongoDB theo ID
    rep.render('update-user', { user }); // Render form update-user với dữ liệu người dùng
    return rep;
});


// Route để xử lý cập nhật thông tin người dùng
fastifyApp.post("/user/:id", { onRequest: [auth, authority("admin")] }, async function(req, rep) {
    // Cập nhật thông tin người dùng theo ID
    const result = await this.mongo.db.collection("users").updateOne({ _id: new ObjectId(req.params.id) }, {
        $set: {
            username: req.body.username,
            role: req.body.role,
            NgaySinh: req.body.NgaySinh,
            SoDT: req.body.SoDT,
            email: req.body.email
        }
    });
    rep.redirect("/users"); // Redirect về trang danh sách người dùng sau khi cập nhật
    // rep.send(result); // Gửi kết quả trả về nếu cần
});


// === Route xóa người dùng và các thư viện liên quan (GET) ===
// Ý nghĩa: Xóa người dùng khỏi hệ thống (chỉ admin được phép thực hiện).
fastifyApp.get(
    "/user/:id", { onRequest: [auth, authority("admin")] }, // Chỉ cho phép admin truy cập
    async function(req, rep) {
        const userId = req.params.id; // Lấy ID của người dùng từ URL

        try {
            // Xóa người dùng từ MongoDB
            const userResult = await this.mongo.db.collection("users").deleteOne({ _id: new ObjectId(userId) });

            // Nếu xóa thành công, xóa thư viện liên quan
            if (userResult.deletedCount > 0) {
                await this.mongo.db.collection("user_libraries").deleteMany({ userId: new ObjectId(userId) });
            }

            // Redirect về danh sách người dùng
            rep.redirect("/users");
        } catch (error) {
            console.error("Lỗi khi xóa người dùng:", error);
            rep.status(500).send({ error: "Lỗi hệ thống khi xóa người dùng và thư viện" });
        }
    }
);




//================================================= SEARCH ====================================================================================================
// Route search (Tìm kiếm)
fastifyApp.get("/search", async function(req, rep) {
    const query = req.query.query; // Lấy từ khóa tìm kiếm từ query string

    // Nếu không có từ khóa tìm kiếm, chuyển hướng về trang chủ
    if (!query) {
        return rep.redirect('/automaker');
    }

    // Chuẩn hóa từ khóa: loại bỏ khoảng trắng thừa và chuyển đổi thành regex
    const sanitizedQuery = query
        .trim() // Loại bỏ khoảng trắng thừa ở đầu và cuối
        .split(/\s+/) // Tách từ khóa thành các từ riêng lẻ
        .map(word => `(?=.*${word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`) // Chuẩn hóa từng từ cho regex
        .join(""); // Kết hợp lại thành regex tìm kiếm toàn chuỗi


    // Tìm kiếm các sản phẩm với tên khớp với từ khóa
    const motos = await this.mongo.db.collection("motos").find({
        TenXe: {
            $regex: sanitizedQuery, // Regex kiểm tra tất cả các từ khóa
            $options: 'i' // Không phân biệt chữ hoa/thường
        }
    }).toArray();

    // Render lại trang chủ với kết quả tìm kiếm
    return rep.render("automaker", {
        motos,
        isLoggedIn: req.user !== undefined,
        username: req.user ? req.user.username : null
    });
});







//================================================= ADMIN-TRANG CHỦ-QUẢN LÝ DANH MỤC SẢN PHẨM) ====================================================================================================
// === Route Hiển Thị Giao Diện Cập Nhật Xe Moto ==
fastifyApp.get("/update-moto/:id", { onRequest: [auth, authority("admin")] }, async function(req, rep) {
    // Tìm kiếm thông tin xe máy theo ID từ MongoDB
    const moto = await this.mongo.db.collection("motos").findOne({ _id: new ObjectId(req.params.id) });

    // Render giao diện cập nhật xe, truyền dữ liệu xe vào view
    rep.render("update-moto", { moto });
    return rep;
});


// === Route Xử Lý Cập Nhật Xe Moto ===
fastifyApp.post("/moto/:id", { onRequest: [auth, authority("admin")] }, async function(req, rep) {
    const { id } = req.params; // Lấy ID xe từ URL
    const parts = req.parts(); // Lấy các phần dữ liệu từ form
    let TenXe, HangXe, DongXe, NamSanXuat, GiaCu, GiaBan, AnhXe, SaleTag;

    // Duyệt qua từng phần dữ liệu trong form (bao gồm cả file và text)
    for await (const part of parts) {
        if (part.file) {
            // Nếu có file được tải lên
            if (!part.filename) continue;
            const uploadPath = path.join(__dirname, "public", part.filename);
            const fileData = await part.toBuffer();
            fs.writeFileSync(uploadPath, fileData);

            // Nếu file là ảnh, lưu đường dẫn ảnh
            if (part.mimetype.startsWith("image/")) {
                AnhXe = `/static/${part.filename}`;
            }
        } else {
            // Lưu các trường text vào biến
            if (part.fieldname === "TenXe") TenXe = part.value;
            else if (part.fieldname === "HangXe") HangXe = part.value;
            else if (part.fieldname === "DongXe") DongXe = part.value;
            else if (part.fieldname === "NamSanXuat") NamSanXuat = part.value;
            else if (part.fieldname === "GiaCu") GiaCu = part.value;
            else if (part.fieldname === "GiaBan") GiaBan = part.value;
            else if (part.fieldname === "SaleTag") SaleTag = part.value;
        }
    }

    // Tạo đối tượng chứa các thông tin cần cập nhật
    const updateData = {};
    if (TenXe) updateData.TenXe = TenXe;
    if (HangXe) updateData.HangXe = HangXe;
    if (DongXe) updateData.DongXe = DongXe;
    if (NamSanXuat) updateData.NamSanXuat = NamSanXuat;
    if (GiaCu) updateData.GiaCu = GiaCu;
    if (GiaBan) updateData.GiaBan = GiaBan;
    if (AnhXe) updateData.AnhXe = AnhXe;
    if (SaleTag) updateData.SaleTag = SaleTag;

    // Kiểm tra nếu không có dữ liệu để cập nhật
    if (Object.keys(updateData).length === 0) {
        return rep.status(400).send({ error: "Không có thông tin nào để cập nhật." });
    }

    // Cập nhật dữ liệu trong MongoDB
    await this.mongo.db.collection("motos").updateOne({ _id: new ObjectId(id) }, { $set: updateData });
    rep.redirect("/motos");
});


// === Route Xóa Xe Máy ==
fastifyApp.get("/moto/:id", { onRequest: [auth, authority("admin")] }, async function(req, rep) {
    // Xóa xe máy khỏi MongoDB theo ID
    await this.mongo.db.collection("motos").deleteOne({ _id: new ObjectId(req.params.id) });

    // Chuyển hướng về danh sách xe
    rep.redirect("/motos");
});


// ==== Route Hiển Thị Danh Sách Xe Máy ==
fastifyApp.get("/motos", { onRequest: [auth, authority("admin")] }, async function(req, rep) {
    // Lấy danh sách xe máy từ MongoDB
    const motos = await this.mongo.db.collection("motos").find().toArray();

    // Render danh sách xe ra giao diện
    rep.render("motos", { motos });
    return rep;
});


// == Route Hiển Thị Giao Diện Tạo Xe Mới ==
fastifyApp.get("/create-moto", { onRequest: [auth, authority("admin")] }, function(req, rep) {
    // Hiển thị form tạo xe mới
    rep.render("create-moto");
});


// == Route Xử Lý Tạo Xe Mới ==
// Ý Nghĩa: Xử lý logic thêm xe máy mới vào cơ sở dữ liệu.
fastifyApp.post("/moto", { onRequest: [auth, authority("admin")] }, async function(req, rep) {
    const parts = req.parts(); // Lấy dữ liệu từ form
    let TenXe, HangXe, DongXe, NamSanXuat, GiaBan, AnhXe, SaleTag;

    // Duyệt qua từng phần dữ liệu trong form
    for await (const part of parts) {
        if (part.file) {
            // Nếu có file được tải lên
            if (!part.filename) continue;
            const uploadPath = path.join(__dirname, "public", part.filename);
            const fileData = await part.toBuffer();
            fs.writeFileSync(uploadPath, fileData);

            // Lưu đường dẫn ảnh
            if (part.mimetype.startsWith("image/")) {
                AnhXe = `/static/${part.filename}`;
            }
        } else {
            // Lưu các trường text vào biến
            if (part.fieldname === "TenXe") TenXe = part.value;
            else if (part.fieldname === "HangXe") HangXe = part.value;
            else if (part.fieldname === "DongXe") DongXe = part.value;
            else if (part.fieldname === "NamSanXuat") NamSanXuat = part.value;
            else if (part.fieldname === "GiaCu") GiaCu = part.value;
            else if (part.fieldname === "GiaBan") GiaBan = part.value;
            else if (part.fieldname === "SaleTag") SaleTag = part.value;
        }
    }

    // Kiểm tra nếu thiếu dữ liệu
    if (!TenXe || !HangXe || !DongXe || !NamSanXuat || !GiaCu || !GiaBan || !SaleTag) {
        return rep.status(400).send({ error: "Vui lòng điền đầy đủ thông tin." });
    }

    // Thêm xe mới vào MongoDB
    await this.mongo.db.collection("motos").insertOne({
        TenXe,
        HangXe,
        DongXe,
        NamSanXuat,
        GiaCu,
        GiaBan,
        AnhXe,
        SaleTag,
    });

    // Chuyển hướng về danh sách xe
    rep.redirect("/motos");
});


fastifyApp.get('/mylibrary/add/:id', async(request, reply) => {
    rep.render('automaker')
    return rep;
});





//================================================= THƯ VIỆN ====================================================================================================
// Route thêm xe vào thư viện của người dùng
fastifyApp.post("/mylibrary/add/:motoId", { onRequest: auth }, async function(req, rep) {
            const userId = req.user.id; // Lấy ID người dùng từ JWT
            const motoId = req.params.motoId; // Lấy ID xe từ URL
            const db = this.mongo.db; // Lấy đối tượng cơ sở dữ liệu MongoDB

            // Tìm xe máy trong MongoDB theo motoId
            const moto = await db.collection("motos").findOne({ _id: new ObjectId(motoId) });
            if (!moto) {
                return rep.redirect(`/automaker?error=${encodeURIComponent("Không tìm thấy xe!")}`); // Nếu không tìm thấy xe máy, trả về lỗi
            }

            // Kiểm tra nếu xe đã có trong thư viện của người dùng
            const existingLibrary = await db.collection("user_libraries").findOne({
                userId: new ObjectId(userId),
                motos: { $elemMatch: { motoId: new ObjectId(motoId) } }, // Kiểm tra nếu xe đã có trong thư viện
            });

            if (existingLibrary) {
                return rep.redirect(`/automaker?info=${encodeURIComponent(`Xe "${moto.TenXe}" đã có trong giỏ hàng của bạn!`)}`); // Xe đã có trong thư viện
    }

    // Thêm xe vào thư viện của người dùng
    const result = await db.collection("user_libraries").updateOne(
        { userId: new ObjectId(userId) },
        {
            $addToSet: { motos: { motoId: new ObjectId(motoId), TenXe: moto.TenXe } }, // Thêm xe mới vào thư viện
        },
        { upsert: true } // Tạo mới thư viện nếu không tồn tại
    );

    // Kiểm tra kết quả và thông báo cho người dùng
    if (result.modifiedCount > 0 || result.upsertedCount > 0) {
        return rep.redirect(`/automaker?success=${encodeURIComponent(`Đã thêm "${moto.TenXe}" vào giỏ hàng của bạn!`)}`);
    }
    return rep.redirect(`/automaker?error=${encodeURIComponent("Không thể thêm xe vào giỏ hàng!")}`);
});

// Route để hiển thị thư viện cá nhân của người dùng
fastifyApp.get("/mylibrary", { onRequest: auth }, async function (req, rep) {
    const userId = req.user.id; // Lấy ID người dùng từ JWT

    // Lấy thư viện của người dùng từ collection `user_libraries`
    const userLibrary = await this.mongo.db.collection("user_libraries").findOne({ userId: new ObjectId(userId) });

    if (!userLibrary || !userLibrary.motos || userLibrary.motos.length === 0) {
        // Nếu thư viện trống, hiển thị thông báo
        return rep.render("mylibrary", { motos: [], message: "Thư viện của bạn đang trống." });
    }

    // Lấy danh sách motoId từ thư viện của người dùng
    const motoIds = userLibrary.motos.map(moto => moto.motoId);

    // Truy vấn tất cả các xe trong `motos` có `motoId` nằm trong danh sách `motoIds`
    const motos = await this.mongo.db.collection("motos").find({ _id: { $in: motoIds } }).toArray();

    // Render template `my-library` và truyền vào danh sách xe máy
    rep.render("mylibrary", { motos });
    return rep;
});

// Reset thư viện (Xóa toàn bộ xe khỏi thư viện)
fastifyApp.post("/mylibrary/reset", { onRequest: auth }, async function (req, rep) {
    const userId = req.user.id; // Lấy ID người dùng từ JWT payload

    // Chuyển đổi `userId` thành `ObjectId`
    const userObjectId = new ObjectId(userId);

    // Kiểm tra xem `userId` có tồn tại trong cơ sở dữ liệu hay không
    const user = await this.mongo.db.collection("users").findOne({ _id: userObjectId });

    // Xóa toàn bộ xe khỏi thư viện của người dùng trong collection user_libraries
    const result = await this.mongo.db.collection("user_libraries").updateOne(
        { userId: userObjectId },
        { $set: { motos: [] } } // Đặt lại mảng motos thành rỗng
    );
    
    // Sau khi reset, chuyển hướng về trang thư viện
    rep.redirect('/mylibrary');
});

  



//==================================================== ROUTES LIÊN QUAN ĐẾN ĐẶT LẠI MẬT KHẨU ======================================================

// Route hiển thị trang yêu cầu đặt lại mật khẩu
fastifyApp.get("/reset-password", function (req, rep) {
    // Render trang yêu cầu đặt lại mật khẩu
    rep.render('reset-password');
  });
  
  
  // Route xử lý yêu cầu đặt lại mật khẩu
  fastifyApp.post('/reset-password', async function (req, rep) {
    const { username, email } = req.body;
  
    // Tìm người dùng dựa trên username và email
    const user = await req.server.mongo.db.collection("users").findOne({ username, email });
    if (!user) {
      // Nếu không tìm thấy người dùng, render lại form với thông báo lỗi
      return rep.render('reset-password', { error: 'Không tìm thấy người dùng' });
    }
  
    // Sinh token ngẫu nhiên và lưu vào cơ sở dữ liệu
    const token = randomBytes(32).toString('hex');
    const tokenExpiry = Date.now() + 3600000; // Token hết hạn sau 1 giờ
  
    // Lưu token vào cơ sở dữ liệu
    await req.server.mongo.db.collection("users").updateOne(
      { _id: user._id },
      { $set: { resetToken: token, resetTokenExpiry: tokenExpiry } }
    );
  
    // Gửi email chứa token cho người dùng để đặt lại mật khẩu
    guiEmailDatLaiMatKhau(email, token);
  
    // Render lại trang yêu cầu đặt lại mật khẩu với thông báo thành công
    rep.render('reset-password', { message: 'Đã gửi email đặt lại mật khẩu' });
    return rep;
  });
  
  // Hàm gửi email với liên kết đặt lại mật khẩu
  function guiEmailDatLaiMatKhau(email, token) {
    // Xây dựng URL để người dùng có thể đặt lại mật khẩu
    const resetUrl = `http://127.0.0.1:3000/update-password?token=${token}`;
    const message = `Vui lòng nhấn vào link sau để đặt lại mật khẩu: ${resetUrl}`;
    
    // Giả lập việc gửi email (sử dụng thư viện như nodemailer)
    console.log(`Email gửi tới ${email}: ${message}`);
  }

  
  // Route hiển thị trang cập nhật mật khẩu
  fastifyApp.get("/update-password", async function (req, rep) {
    const { token } = req.query; // Lấy token từ query string trong URL
    if (!token) {
      return rep.status(400).send({ error: 'Thiếu token trong yêu cầu' }); // Nếu không có token, trả về lỗi
    }
  
    try {
      // Tìm người dùng với token reset
      const user = await req.server.mongo.db.collection("users").findOne({ resetToken: token });
      if (!user) {
        return rep.status(400).send({ error: 'Token không hợp lệ' }); // Token không hợp lệ
      }
      if (user.resetTokenExpiry < Date.now()) {
        return rep.status(400).send({ error: 'Token đã hết hạn' }); // Token đã hết hạn
      }
  
      // Render trang cập nhật mật khẩu với token hợp lệ
      return rep.render('update-password', { token, message: null });
    } catch (error) {
      return rep.status(500).send({ error: 'Lỗi hệ thống' }); // Nếu có lỗi hệ thống, trả về lỗi
    }
  });
  

  // Route xử lý cập nhật mật khẩu
  fastifyApp.post('/update-password', async function (req, rep) {
    const { token, matKhauMoi } = req.body; // Lấy token và mật khẩu mới từ form
  
    // Tìm người dùng theo token
    const user = await req.server.mongo.db.collection("users").findOne({
      resetToken: token
    });
  
    if (!user) {
      // Trả lại thông báo lỗi nếu token không hợp lệ
      return rep.render('update-password', { token, message: 'Tên người dùng hoặc token không hợp lệ' });
    }
  
    // Kiểm tra token hết hạn
    if (user.resetTokenExpiry < Date.now()) {
      return rep.render('update-password', { token, message: 'Token đã hết hạn' });
    }
  
    // Mã hóa mật khẩu mới trước khi lưu
    const salt = randomBytes(16).toString('hex');
    const hashedPassword = createHmac("sha256", salt).update(matKhauMoi).digest("hex");
  
    // Cập nhật mật khẩu và xóa token
    await this.mongo.db.collection("users").updateOne(
      { _id: user._id },
      { $set: { hpass: hashedPassword, salt }, $unset: { resetToken: '', resetTokenExpiry: '' } }
    );
  
    // Render lại trang cập nhật mật khẩu với thông báo thành công
    return rep.render('update-password', { token, message: 'Mật khẩu đã được cập nhật thành công' });
  });






//==================================================== ROUTES CONTACT ======================================================

fastifyApp.post("/contact", async function (req, rep) {
  const { name, email, message } = req.body;

  // Lưu thông tin liên hệ vào collection "contacts"
  const result = await this.mongo.db.collection("contacts").insertOne({
    name,
    email,
    message,
    createdAt: new Date()
  });

  if (result.insertedCount === 1) {
    // Hiển thị thông báo thành công
    return rep.render('contact', { success: "Tin nhắn của bạn đã được gửi thành công!" });
  } else {
    // Hiển thị thông báo lỗi
    return rep.render('contact', { error: "Đã xảy ra lỗi khi gửi tin nhắn của bạn. Vui lòng thử lại sau." });
  }
});

fastifyApp.get("/about", async function (req, rep) {
  return rep.render('about');
});


// == Run the server! ==
fastifyApp.listen({ port: 3000 }, (err) => {
    if (err) {
      fastify.log.error(err); // Ghi lỗi nếu có sự cố xảy ra
      process.exit(1); // Dừng quá trình nếu có lỗi
    }
  });