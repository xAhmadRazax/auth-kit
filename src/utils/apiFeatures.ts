// import { Query } from "mongoose";
// import { ParsedQs } from "qs";
// export class ApiFeatures<T> {
//   constructor(
//     public queryBuilder: Query<T[], T>,
//     public queryObj: ParsedQs
//   ) {}

//   filter() {
//     const TempQueryObj = { ...this.queryObj };
//     const fieldsToExcludes = ["sort", "page", "fields", "limit"];
//     fieldsToExcludes.forEach((field) => delete TempQueryObj[field]);

//     let queryStr = JSON.stringify(TempQueryObj);
//     queryStr = queryStr.replace(/(gte|gt|lt|lte)/, (match) => `$${match}`);
//     this.queryBuilder = this.queryBuilder.find(JSON.parse(queryStr));

//     return this;
//   }
//   sort() {
//     if (this.queryObj?.sort && typeof this?.queryObj?.sort === "string") {
//       const sortBy = this.queryObj.sort?.split(",").join(" ");

//       this.queryBuilder = this.queryBuilder.sort(sortBy);
//     } else {
//       this.queryBuilder.sort("-createAt");
//     }

//     return this;
//   }
//   limitFields() {
//     if (this.queryObj?.fields && typeof this?.queryObj?.fields === "string") {
//       const sortBy = this.queryObj.fields?.split(",").join(" ");

//       this.queryBuilder = this.queryBuilder.select(sortBy);
//     } else {
//       this.queryBuilder.select("-__v");
//     }
//     return this;
//   }

//   paginate() {
//     const page = Number(this.queryObj.page) || 1;
//     const limit = Number(this.queryObj.limit) || 100;
//     const skip = (page - 1) * limit;

//     this.queryBuilder = this.queryBuilder.skip(skip).limit(limit);
//     return this;
//   }
// }
