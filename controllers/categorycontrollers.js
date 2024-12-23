const express=require("express")
const app=express()
const router=express.Router()
const db=require("../db")
const SubCategoryController=()=>{
    console.log("hi i am subcategory controller")
   
}
const addsubcategory=async(req,res)=>{
    try{
        const {subcategoryName,categoryId}=req.body
   
        const result=await db.promise().query("insert into subcategory (subcategoryName,categoryId) values (?,?)",[subcategoryName,categoryId])
    res.send(result)
    }
    catch(err){
console.log(err);
res.send()
    }
 
}
const fetchsubcategory=async(req,res)=>{
    try{
        console.log("hi fetch sub category");
       
    const subcategoryq=await db.promise().query("select * from subcategory")
    console.log("hi i am subcategory");
    console.log(subcategoryq)
    res.send(subcategoryq[0])}
    catch(err)
    {res.status(500).send(err)}
}
const editsubcategory=async(req,res)=>{
    try{
        const id=req.params.id
        const subcategory=await db.promise().query("update subcategory set ? where subcategoryId=?",[subcategory, id])
        res.send(s)
    }
    catch(err){
        res.status(500).send(err)
 
    }
 
}
const deletesubcategory=async(req,res)=>{
    try{
        const id=req.params.id
        console.log(id)
        const subcategory=db.promise().query("delete from subcategory where subcategoryId=?",id)
        res.send("deleted successfully")
 
    }
    catch(err){
        res.send(err)
    }
 
}
module.exports={
    addsubcategory,
    fetchsubcategory,
    editsubcategory,
    deletesubcategory
}