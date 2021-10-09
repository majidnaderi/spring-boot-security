package ir.learning.springbootsecurity.student;

public class Student {

    private final Integer studentId;
    private final String StudentName;

    public Student(Integer studentId, String studentName) {
        this.studentId = studentId;
        StudentName = studentName;
    }

    public Integer getStudentId() {
        return studentId;
    }

    public String getStudentName() {
        return StudentName;
    }
}
