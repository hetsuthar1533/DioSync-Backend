const express=require("express")
const app=express()
app.use(express.json())
const cors=require("cors")
app.use(cors({
    origin: "http://localhost:3000",
    credentials:true
}))


app.use(express.urlencoded({ extended: true }));

const db=require("../db");
 const ContactController=(req,res)=>{
    res.status(200).send("sent success")
}
const AddContact = async (req, res) => {
    try {
         const {username,email,phone_number,reply} = req.body;

console.log(req.body);
        const date1=new Date()

            await db.promise().query(
                "INSERT INTO contact ( username,email,phone_number,reply,inquiry_date) VALUES (?, ?, ?,?,?)",
                [ username,email,phone_number,reply,date1]
            );

            res.status(200).json({
                message: "contacted successfully",
                data: {
username,email,phone_number,reply
 }
            });
        }
     catch (err) {
        console.error(err);
        res.status(500).send("Internal server error");
    }
};

const getAllContact = async (req, res) => {
    try {
        const [contact] = await db.promise().query("SELECT * FROM contact");

       

        res.status(200).json({
            success: true,
            message: "contact fetched successfully",
            data: contact,
        });
    } catch (error) {
        console.error("Failed to fetch contact", error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch contact",
        });
    }
};
const getContactByDate=async(req,res)=>{   try {
    const [contact] = await db.promise().query("SELECT count(*) as contact_count,inquiry_date FROM contact group by inquiry_date");

   

    res.status(200).json({
        success: true,
        message: "contact fetched successfully",
        data: contact,
    });
} catch (error) {
    console.error("Failed to fetch contact", error);
    res.status(500).json({
        success: false,
        message: "Failed to fetch contact",
    });
}}
const deleteContact=async(req,res)=>{
    try{
        console.log("hi i am delete contact");
        const id=req.params;
        console.log(id);
        console.log("hi i am delete contact");
        await db.promise().query("delete from contact where contactId=?",[id.id])
        
        res.status(200).send("delete success")
    }
    catch(error){
        res.status(500).json({
            success: false,
            message: "Failed to fetch contact",
        });
    }
    

    
}
const editContact=async(req,res)=>{
    try{
        console.log("hi i am edit contact");
        console.log(req.body);
        
        const reply = req.body;
        const id=req.params.id;
        console.log(id);
        if(reply)
        {
            await db.promise().query("update contact set reply=? where contactId=?  ",[reply,id])
            console.log("reply updated");

        }
     
  
        
  
        res.status(200).send("Updated successfully")


        }


 
    catch(error)
    {
res.send(error)
    }
}

module.exports = { 
    AddContact, 
    getAllContact,
    deleteContact,
    editContact,
    getContactByDate,
    ContactController
  };
  